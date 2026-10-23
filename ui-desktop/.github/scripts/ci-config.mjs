// Generates the override config used by `tauri build --config ci-override.json`.
//
// Four things are overridden (`--config` is deep-merged into tauri.conf.json; arrays
// are replaced wholesale):
//   1. bundle.resources       —— on Windows pick wintun.dll by target arch so an arm64
//      bundle never ships the amd64 DLL
//   2. bundle.createUpdaterArtifacts —— enabled only when a signing private key is
//      configured, otherwise the build errors out
//   3. bundle.windows.certificateThumbprint —— the Authenticode certificate the
//      Windows bundle is signed with, read back from the certificate the workflow
//      imported. It is a deployment value, so it cannot live in tauri.conf.json.
//   4. build.beforeBuildCommand —— always npm, so we do not depend on yarn being
//      installed on the runner
//
// Environment variables:
//   MATRIX_OS       windows | macos | linux
//   MATRIX_ARCH     amd64 | arm64
//   MATRIX_TARGET   cargo target triple (currently only used for logging)
//   SIGNING_ENABLED "true" / "false"
//   WINDOWS_CERTIFICATE_THUMBPRINT  the thumbprint of the imported Authenticode
//      certificate; empty on the platforms that do not sign with one
import fs from "node:fs";

const os = process.env.MATRIX_OS ?? "";
const arch = process.env.MATRIX_ARCH ?? "";
const target = process.env.MATRIX_TARGET ?? "";
const signingEnabled = process.env.SIGNING_ENABLED === "true";
const windowsThumbprint = process.env.WINDOWS_CERTIFICATE_THUMBPRINT ?? "";

if (!os || !arch) {
  console.error("::error::missing MATRIX_OS / MATRIX_ARCH environment variables");
  process.exit(1);
}

// wintun.dll is only used on Windows and must match the process architecture:
// the driver DLL is loaded through LoadLibrary by tun / wintun-bindings, and an
// architecture mismatch fails outright.
// On non-Windows platforms the array is emptied so we never reference a path that does
// not exist in the repo.
const resources =
  os === "windows" ? [`wintun/bin/${arch === "arm64" ? "arm64" : "amd64"}/wintun.dll`] : [];

// The Authenticode certificate is named by its thumbprint, and the certificate
// lives in the runner's own certificate store — it is imported by the workflow
// before the build. Without a thumbprint Tauri signs nothing, so the bundle
// would be published unsigned; the workflow refuses to get this far without a
// certificate, and the value is empty only when the platform opted out of
// signing on purpose.
const windows =
  os === "windows" && windowsThumbprint
    ? { certificateThumbprint: windowsThumbprint }
    : undefined;

const override = {
  build: {
    beforeBuildCommand: "npm run build",
  },
  bundle: {
    createUpdaterArtifacts: signingEnabled,
    resources,
    ...(windows ? { windows } : {}),
  },
};

const outPath = "ci-override.json";
fs.writeFileSync(outPath, `${JSON.stringify(override, null, 2)}\n`);

console.log(`Generated ${outPath} (os=${os}, arch=${arch}, target=${target}):`);
console.log(fs.readFileSync(outPath, "utf8"));
