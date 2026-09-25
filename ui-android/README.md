# NexaPipe Android client

Android client for [NexaPipe](https://github.com/open-nexa/nexapipe). It captures
the traffic of selected domains through a `VpnService` TUN interface and forwards
it to a NexaPipe server over iroh/QUIC — the server needs no public IP and no
open port.

This tree is part of the NexaPipe monorepo (`ui-android/`); its git history was
preserved when it was imported from the former standalone repository,
<https://github.com/open-nexa/nexa-android>.

---

## How it works

The app is deliberately **not** a full-tunnel VPN:

```
 app (browser, …)
      │  DNS query for a proxied domain
      ▼
 VpnService TUN            Builder: setMtu(1400), addRoute("10.0.1.0", 24),
      │                    addDnsServer(<virtual DNS>)
      ▼
 Rust: smoltcp userspace TCP/IP stack   (crates/nexapipe-client, feature tun-proxy)
      │  · DNS answers point the domain at the fake proxy IP
      │  · inner TCP is terminated locally; each connection = one QUIC bi-stream
      ▼
 iroh endpoint (ALPN b"\x05nexapipe") ── QUIC ──▶ nexapipe server ──▶ real backend
```

Only the domains you configure are hijacked; everything else keeps using the
normal network. `UnderlyingNetworkSelector` keeps the TUN on a validated network
so the tunnel survives Wi-Fi ↔ cellular switches.

---

## Features

- Per-domain routing: a list of server nodes, each owning a set of domains.
- Domain hijack + TCP redirect with a smoltcp userspace stack on the Rust side
  (the old hand-written Kotlin TCP stack is gone).
- Relay control: `pinned` (default), `default`, `custom` URL (with an optional
  auth token), or `disabled`. There is no "force relay" switch: iroh 1.0.1 gives
  no way to keep a connection relayed, so one is not offered.
- DNS workarounds for hostile networks: system DNS servers are injected into
  Rust (`nativeSetDnsServers`), and iroh infrastructure domains can be
  pre-resolved and pinned (`nativeSetDnsOverride`).
- TOTP 2FA: scan an `otpauth://` QR code with CameraX + ZXing (no Google Play
  Services, works offline), or export your own credentials as a QR code.
- Pre-connect warm-up so the first request after the VPN comes up does not wait
  for the QUIC/relay handshake.
- Jetpack Compose UI (`VpnControlScreen`, `PermissionGuideScreen`), node list
  and settings persisted in `SharedPreferences`.

---

## Requirements

| | |
| --- | --- |
| Android Studio | Recent release with AGP + Kotlin Compose support |
| JDK | 17 |
| compileSdk / targetSdk | 36 |
| minSdk | 26 (Android 8.0) |
| ABI | `arm64-v8a` only |
| NDK | r26 or newer (CI pins `29.0.14206865`) |
| Rust | stable + `cargo-ndk`, plus the `aarch64-linux-android` target |

---

## Building

The native library is **not** committed: `app/src/main/jniLibs/` is gitignored.
Build it from the parent workspace first.

### 1. Build `libnexapipe_client.so`

From the **repository root**:

```powershell
cargo ndk --target arm64-v8a --platform 26 build --release `
  -p nexapipe-client --features jni,tun-proxy
```

Then copy it in (the file name is fixed by `System.loadLibrary("nexapipe_client")`):

```
target/aarch64-linux-android/release/libnexapipe_client.so
  → ui-android/app/src/main/jniLibs/arm64-v8a/libnexapipe_client.so
```

`tun-proxy` implies `local-proxy` and is what compiles `nativeStartTunProxy`.
Build without it and the VPN dies with `UnsatisfiedLinkError` on device.

### 2. One-shot debug loop (recommended)

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_android.ps1
```

It does everything: preflight (cargo-ndk, adb, SDK, NDK, device) → Rust build →
verify the exported JNI symbols → copy the `.so` → `gradlew :app:installDebug` →
launch → smoke check → stream logcat into `nexa_vpn_log.txt`.

Useful switches: `-BuildOnly` (build and verify, no device), `-Restart` (cold
start), `-SkipRust`, `-SkipInstall`, `-SkipLaunch`, `-NoLog`, `-Check`
(diagnostics only), `-Serial <serial>`.

> `VpnService.prepare()` shows a system dialog that adb cannot accept — the
> first connection still needs one tap.

### 3. Gradle only

```powershell
.\gradlew :app:installDebug          # build + install
.\gradlew :app:assembleRelease       # release APK
.\gradlew :app:compileDebugKotlin    # compile check
.\gradlew :app:test                  # unit tests (incl. OtpAuthUri parsing)
```

---

## Native (JNI) surface

`com.nexa.pipe.IrohProxy` is a 1:1 Kotlin mirror of
`crates/nexapipe-client/src/jni.rs`.

| Method | Purpose |
| --- | --- |
| `nativeInit()` | Called from the `init` block; loads and initializes Rust. |
| `nativeSetDnsServers(csv)` | Inject system DNS servers (must precede `nativeStartIroh`). |
| `nativeSetDnsOverride("d=ip,ip;…")` | Pin pre-resolved IPs for iroh domains. |
| `nativeSetRelayConfig(mode, url)` | `default` / `disabled` / `custom`. |
| `nativeSetTwoFactorForNode(nodeId, id, secret, alg)` | TOTP credentials of one endpoint. |
| `nativeClearNodeTwoFactor()` | Drop every per-endpoint credential before re-reading them. |
| `nativeSetTwoFactor(id, secret, alg)` | TOTP credentials shared by *every* endpoint; per-endpoint ones win. |
| `nativeStartIroh()` | Bring up the endpoint; returns the Node ID. |
| `nativeStartProxy(port)` | Start the local proxy and the endpoint group. |
| `nativePreconnect()` | Warm up one connection per configured backend. |
| `nativeStartTunProxy(fd, domains)` | Hand the detached TUN fd to Rust. |
| `nativeStopTunProxy()` / `nativeStopProxy()` / `nativeDestroy()` | Teardown. |
| `nativeAddNode` / `nativeAddDomainMapping` / `nativeRemoveNode` / `nativeClearNodes` / `nativeAddDomain` / `nativeRemoveDomain` | Routing table. |

All of them return `0` on success and `-1` on failure (except
`nativeStartIroh`, which returns the Node ID, and `nativePreconnect`, which
returns the number of warmed backends).

---

## Layout

```
app/src/main/java/com/nexa/pipe/
├── MainActivity.kt              Compose entry point
├── IrohProxy.kt                 JNI declarations + library load
├── SettingsManager.kt           SharedPreferences (nodes, relay, 2FA)
├── PermissionManager.kt         VPN + camera permission flow
├── vpn/
│   ├── NexaVpnService.kt        VpnService, TUN builder, fd handover
│   └── UnderlyingNetworkSelector.kt
├── otp/OtpAuthUri.kt            otpauth:// parsing/serialization
└── ui/                          Screens, ViewModel, QR scan/export dialogs
```

---

## Release signing

`app/build.gradle.kts` reads signing config from `keystore.properties` (local,
gitignored) and falls back to environment variables in CI:

```
storeFile / storePassword / keyAlias / keyPassword
RELEASE_KEYSTORE_PATH / RELEASE_KEYSTORE_PASSWORD / RELEASE_KEY_ALIAS / RELEASE_KEY_PASSWORD
```

Pushing a `v*` tag runs `.github/workflows/release-apk.yml`: it checks out the
upstream Rust repo, cross-compiles the `.so` with cargo-ndk, verifies the
required JNI symbols, assembles and signs the APK, verifies it with
`apksigner`, and publishes a GitHub Release. The workflow can also be dispatched
manually with `signing_only` to validate the signing secrets in about a minute.

A version whose name contains a hyphen (`v0.2.0-rc.1`, `v0.2.0-beta.1`) is
published as a **pre-release**, so it never takes over "latest"; a plain version
(`v1.0.0`) is published as a normal release. This is the same rule as
`ui-desktop`.

Local pre-flight:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify-signing-secrets.ps1
```

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `UnsatisfiedLinkError: nativeStartTunProxy` | The `.so` was built without the `tun-proxy` feature. |
| `UnsatisfiedLinkError` on `System.loadLibrary` | The `.so` is missing from `jniLibs/arm64-v8a/` or the ABI filter does not match the device. |
| Tunnel connects then drops after a few seconds | Usually the smoltcp sequence-number underflow panic — make sure the workspace `[patch.crates-io]` for `third_party/smoltcp` is in effect. |
| iroh never connects / `dns.iroh.link` timeouts | Set a relay override, or inject DNS servers (both are exposed in the UI). |
| Poor throughput over long RTT links | Raise `NEXAPIPE_QUIC_STREAM_WINDOW` (see the root README). |

Logs: `adb logcat` filtered on the app tags, or `nexa_vpn_log.txt` when using
`run_android.ps1`.

---

## License

MIT — see the [LICENSE](https://github.com/open-nexa/nexapipe/blob/main/LICENSE)
in the parent repository.
