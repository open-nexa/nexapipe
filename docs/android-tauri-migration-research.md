# 调研：Android 现状 & 迁移到 Tauri 2.0 的可行性

> 调研日期 2026-09-23。本文只做现状梳理与可行性评估，**未修改任何代码**。
> 结论先行：**技术上可以迁，长期看也值得；但它是一个分阶段的工程，不是一次 UI 重写。**

---

## 一、Android 端现在到底跑不跑 service？

**跑，而且是关键路径上的 Android Service。** 一共三层东西在跑，只有第一层是真正的 Service。

### 1. `NexaVpnService`（真正的 Android Service，前台服务）

| 项 | 值 |
| --- | --- |
| 文件 | `ui-android/app/src/main/java/com/nexa/pipe/vpn/NexaVpnService.kt`（712 行） |
| 父类 | `android.net.VpnService` |
| Manifest | `android:permission="android.permission.BIND_VPN_SERVICE"`<br>`android:exported="false"`<br>`android:foregroundServiceType="specialUse"`<br>`PROPERTY_SPECIAL_USE_FGS_SUBTYPE = vpn`<br>intent-filter `android.net.VpnService` |
| 权限 | `INTERNET` / `ACCESS_NETWORK_STATE` / `FOREGROUND_SERVICE`<br>`FOREGROUND_SERVICE_SPECIAL_USE` / `POST_NOTIFICATIONS` / `CAMERA`(optional) |
| 启动 | `VpnViewModel.connect()` → `context.startForegroundService(ACTION_START)`（`VpnViewModel.kt:762`） |
| 停止 | `context.startService(ACTION_STOP)`（`VpnViewModel.kt:611`） |
| `onStartCommand` | 返回 `START_STICKY` |

它实际做的事：

1. `onCreate`：注册 `ConnectivityManager.NetworkCallback`（只要求 `NET_CAPABILITY_INTERNET`，**故意不要求 VALIDATED**，因为运营商会劫持连通性检查导致 Wi-Fi 永不 validated）。
2. `establishVPN()`：`Builder().setMtu(1400).setSession("Nexa").addAddress("10.0.1.1", 24).addRoute("10.0.1.0", 24).addDnsServer("10.0.1.2").addDisallowedApplication(自身包名).setUnderlyingNetworks(选中的物理网络)`，然后 `establish() → detachFd()`，**把 fd 交给 Rust**：`IrohProxy.nativeStartTunProxy(fd, domains)`。
3. `startForeground(1, notification)`，channel `NexaVPN`。
4. `onRevoke()`：被别的 VPN（Clash 之类）抢走 slot 时，同步复位所有会话标志并拆除，避免"VPN 互相抢"。
5. 网络切换重连：`onUnderlyingNetworkChanged` → 去抖 1.5s → `reconnectTunnel()`（Mutex 串行，最多 3 次，单次 60s 超时，handover 等待 120s）→ `nativeStopTunProxy` → `nativeDropConnections` → 重新 establish → `nativePreconnect`。
6. 进程级静态标志 `isServiceActive` / `wasRevoked` + `revokedListener` / `brokenListener`，供 ViewModel 在 Activity 重建后对齐 UI 状态。

### 2. 进程内本地 HTTP 代理（**不是** Android Service）

`IrohProxy.nativeStartProxy(8080)` 起的是一个 tokio listener，跑在 app 进程里，端口冲突时递增重试 8080..8089。
按 `VpnViewModel.kt` 里 `LOCAL_PROXY_PORT` 的注释：**TUN 模式下数据并不走它，只用于 preconnect 预热**。

### 3. 没有的东西

- 没有桌面端那种独立服务进程 + IPC（`nexa-service` / `127.0.0.1:12345` NDJSON）是 Windows 独有的。
- 没有自定义 TCP/IP 协议栈（老的 ~1600 行 Kotlin 栈已删除，现在是 Rust `netstack-smoltcp`）。

---

## 二、规模盘点

| 模块 | 位置 | 行数 |
| --- | --- | --- |
| Android Kotlin 总计 | `ui-android/app/src/main/java/com/nexa/pipe/` | **6 166** |
| ├ `VpnViewModel` | `ui/` | 988 |
| ├ `VpnControlScreen`（Compose） | `ui/` | 926 |
| ├ `EndpointDetailScreen`（Compose） | `ui/` | 819 |
| ├ `NexaVpnService` | `vpn/` | 712 |
| ├ `QrScannerDialog`（CameraX + ZXing） | `ui/` | 443 |
| ├ `EndpointInvite` | `provisioning/` | 404 |
| ├ `OtpAuthUri` | `otp/` | 267 |
| ├ `IrohProxy`（JNI 声明，24 个 external） | 根 | 216 |
| ├ 其余（Settings / Permission / theme / 组件） | | ~1 391 |
| Rust JNI 层 | `crates/nexapipe-client/src/jni.rs` | **2 230** |
| Rust Android TUN（smoltcp over fd） | `crates/nexapipe-client/src/tun_proxy.rs` | 1 075 |
| 桌面前端（Vue/TS） | `ui-desktop/src/` | **9 312** |
| 桌面 Rust 后端 | `ui-desktop/src-tauri/src/` | ~5 000 |
| 桌面 TUN（真设备 wintun/utun） | `ui-desktop/src-tauri/src/proxy/tun_proxy.rs` | 827 |

两端当前依赖：`nexapipe-client` 桌面只开 `local-proxy`，Android 开 `jni` + `tun-proxy`。

---

## 三、Tauri 2.0 能承载这个 App 吗？

### 3.1 能。关键能力都已具备（官方支持）

| 需求 | Tauri 2 的支撑 |
| --- | --- |
| Android 移动端 | 官方支持；本项目桌面端已在 tauri **2.11.5** |
| 写 Kotlin 原生代码 | `@TauriPlugin` + `@Command` 的 Kotlin 插件类，继承 `app.tauri.plugin.Plugin` |
| Rust → Kotlin | `PluginHandle::run_mobile_plugin("cmd", payload)`，返回值 serde 反序列化 → **Kotlin 可以把 `detachFd()` 得到的 int 直接返回给 Rust** |
| Kotlin → Rust | ① JNI（`System.loadLibrary` 应用 cdylib + `external fun` + `Java_xxx` 导出）；② `trigger("event", JSObject)` 推事件给前端 |
| 权限 | `@TauriPlugin(permissions = [Permission(strings = [...], alias = ...)])`，自动生成 `checkPermissions` / `requestPermissions` |
| Service / Manifest | `tauri android init` 生成的 `gen/android` 是**你持有、提交、可编辑**的完整 Gradle 工程；官方明确说可以为权限等平台需求定制它 |
| minSdk | 默认 24，可用 `bundle.android.minSdkVersion` 提到 26（现 app 26，compileSdk/targetSdk 36） |
| QR 扫描 | 官方 `tauri-plugin-barcode-scanner`（Android/iOS，2.4.6） |
| 通知 | 官方 `tauri-plugin-notification` |
| 持久化 | `tauri-plugin-store` / `sql`，或 Rust 直接写 `appLocalDataDir` |
| 调试 | Chrome DevTools 直连 WebView；Rust 侧 lldb/日志 |

### 3.2 迁移后的目标架构

```
                       Vue 前端（桌面/移动共用 stores·i18n·api·types）
                                    │  invoke / listen
                       Tauri Rust 核心（libnexa_lib.so）
                     ┌──────────────┴───────────────┐
              #[cfg(desktop)]                 #[cfg(mobile)]
        真 TUN 设备（wintun/utun）        run_mobile_plugin("vpn","start")
        nexa-service + IPC（Windows）              │
                                          Kotlin 插件 tauri-plugin-nexa-vpn
                                          ├ NexaVpnService（establish→detachFd）
                                          ├ UnderlyingNetworkSelector
                                          └ 通知 / 相机
                                                  │ fd: Int
                                          smoltcp TUN proxy（tun-proxy feature）
                                                  │
                                             iroh → nexapipe server
```

**Kotlin 从 6 166 行降到约 1 000 行**（只留 VpnService + 网络选择 + 权限），JNI 层 2 230 行的胶水部分消失。

---

## 四、成本与风险（这部分才是重点）

### ⚠️ 风险 1：`jni.rs` 的 2 230 行不是胶水，是业务逻辑

它里面装着一堆**桌面端完全没有**的 Android 网络适配：

- `CUSTOM_DNS_SERVERS` + 自定义 `DnsResolver` —— 因为 iroh 走 JNI 读 Android 系统 DNS 会失败并回落到 8.8.8.8，所以 Kotlin 从 `ConnectivityManager` 读出来注入 Rust。
- `DNS_OVERRIDES` + `OverrideResolver` —— 预解析 `dns.iroh.link` / `*.relay.n0.iroh.link`，绕开 GFW 丢弃 iroh.link 的 UDP DNS 响应。
- `RELAY_MODE` / `CUSTOM_RELAY_URL` / `RELAY_AUTH_TOKEN`
- `NODE_TWO_FACTOR`（每端点一套 2FA 凭据）
- `ENDPOINT_GEN`（世代计数，防止"迟到的 endpoint 复活已释放的隧道"）
- `LAST_ERROR`（`nativeTakeLastError` 的人话错误原因）

已 grep 确认：`ui-desktop/src-tauri/src/` 里**一个都没有**。
所以迁移必须先把这些抽到 `crates/nexapipe-client` 的平台无关模块，否则 Android 会整体丢掉"国内网络可用"的适配。**这是整个迁移中最容易低估的一项。**

### ⚠️ 风险 2：Kotlin 不会消失，只是变薄

`VpnService` / `ConnectivityManager` / 通知 / 相机无法用 Web 技术替代。迁移的本质是
"Kotlin 6 166 行 → 约 1 000 行的平台插件"，而不是"消灭 Kotlin"。

### ⚠️ 风险 3：进程 / Activity 生命周期要真机验证

Tauri 的 Rust `run()` 与 Activity 绑定。Activity 被销毁（返回退出、被划掉）后靠前台服务保活进程时，Rust 侧静态状态（endpoint / 连接池 / TUN）是否还在，必须实测。
现在的状态本来就放在 native 静态变量 + service 静态变量里，天然扛得住 Activity 重建；Tauri 下很容易不小心把状态挂到 `AppHandle` / WebView 上，一销毁就没了。

### ⚠️ 风险 4：系统 DNS 注入链路变长

`getSystemDnsServers` / `resolveIrohDnsOverrides` / `UnderlyingNetworkSelector` 都依赖 ConnectivityManager，迁移后仍是 Kotlin 读、Rust 用，但路径变成
`Kotlin → plugin invoke → 前端 / Kotlin → JNI → Rust`。
**必须在 `start_iroh` 之前完成注入**，顺序要在设计阶段定死。

### ⚠️ 风险 5：桌面 UI 不能直接搬

桌面 9 312 行前端带自绘标题栏、窗口控制、侧边栏、Windows 服务管理（`ServiceManager.vue` 496 行），起始窗口 1000×680。手机需要另一套 shell（单列 / 底部导航）。
可复用的：stores（proxy / config / prefs）、`api/errors.ts`、`api/invite.ts`、i18n、`types`、base 组件、纯逻辑解析。
要重做的：ConfigPage(1049) / SettingsPage(694) / DashboardPage(538) 的移动布局 + 移动 shell。**前端复用率粗估 50–60%**。

### ⚠️ 风险 6：系统 WebView 依赖

Tauri Android 用系统 WebView（不内置 Chromium）。国内 ROM 一般自带但版本碎片化，需要真机回归。
另外要实测：**WebView 的流量是否和 app 同 UID、被 `addDisallowedApplication` 一并排除**（理论上是，但未验证）。

### ⚠️ 风险 7：QR 插件的取舍

官方 `barcode-scanner` 走 CameraX + ML Kit（bundled 版无需 GMS，但体积增加）。现在是 CameraX + ZXing core，APK 更小且明确无 GMS 依赖。在意的话自己写插件沿用什么都不用改。

### ⚠️ 风险 8：两端 TUN 数据面本来就是两套

桌面是真 TUN 设备（wintun / utun，827 行），Android 是 smoltcp 跑在 VpnService 的 fd 上（1 075 行）。**不要指望顺手合并**。
Android 侧继续用 `crates/nexapipe-client` 的 `tun-proxy` feature（它已经 `cfg(target_os = "android")`，不依赖 `jni` feature）。

### ⚠️ 风险 9：构建链与仓库结构变化

- Android 构建从 `build_android.bat` + cargo-ndk 出 `libnexapipe_client.so`，变成 `tauri android init/dev/build` + 4 个 rustup target。
- `ui-android` 是独立 submodule 仓库（github.com/open-nexa/nexa-android），迁移意味着它要么归档，要么退化成"只放 Kotlin 插件"。
- 桌面端会新增 `#[cfg(desktop)]` / `#[cfg(mobile)]` 分支，以及 `tauri.android.conf.json`、mobile capabilities。

### ⚠️ 风险 10：iOS 不要绑在这次一起做

Tauri 支持 Swift 插件，理论上能顺势做 iOS（`NEPacketTunnelProvider`），但那是另一个量级的工作（Apple 的 Network Extension  entitlement 要单独申请）。建议拆开。

---

## 五、建议路径（如果要做）

| 阶段 | 内容 | 目的 |
| --- | --- | --- |
| **0** | 把 `jni.rs` 里的 DNS / relay / 2FA / endpoint-gen / last-error 逻辑抽到 `crates/nexapipe-client` 的平台无关模块，JNI 与未来的 Tauri 共用 | 单独做也有价值；拆掉最大风险 |
| **1** | `tauri android init`，写一个只做"建 VPN、返回 fd"的最小 Kotlin 插件，验证 Rust 拿到 fd 能起 smoltcp TUN proxy | 打掉唯一的结构性风险 |
| **2** | 把网络回调、重连、`onRevoke`、DNS 注入搬进插件，用 `trigger` 把状态推给前端 | 恢复现有全部行为 |
| **3** | Vue 移动端 shell + 复用 stores / i18n；QR 用官方或自写插件 | 完成 UI |
| **4** | 真机验证进程保活、网络切换、WebView 流量排除、GFW 场景；然后下线 `ui-android` | 收尾 |

---

## 六、一句话结论

**可以迁。**主要收益是消灭 JNI 层、统一 Rust 核心（现在 Android 走 2 230 行 `jni.rs`、桌面走 571 行 `manager.rs`，两套状态机/错误码），长期维护成本显著下降。
但真正的硬骨头是 **① `jni.rs` 里 Android 网络适配逻辑的抽取** 和 **② Kotlin 插件与 Tauri Activity 生命周期的对齐**，都不是 UI 层面能解决的。

- 如果目标是"少维护一套 UI" → 收益可能不抵风险。
- 如果目标是"统一前后端状态机与错误处理" → 值得做，按上面 0→4 推进。
