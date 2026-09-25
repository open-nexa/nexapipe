// Collects the Tauri bundle output into a flat, publish-ready release-artifact/
// directory and picks out this platform's updater payload (with its .sig signature) so
// latest.json can be generated afterwards.
//
// Environment variables:
//   MATRIX_OS      windows | macos | linux
//   MATRIX_ARCH    amd64 | arm64
//   MATRIX_TARGET  cargo target triple
//   TARGET_DIR     cargo target directory (usually src-tauri/target)
//   VERSION        version number (without the leading v)
//
// Written to $GITHUB_OUTPUT:
//   updater_file=   updater payload file name (inside release-artifact/)
//   renamed=       true/false, whether it was renamed to avoid a name clash (a rename
//                  means it has to be signed again)
import fs from "node:fs";
import path from "node:path";

const os = process.env.MATRIX_OS ?? "";
const arch = process.env.MATRIX_ARCH ?? "";
const target = process.env.MATRIX_TARGET ?? "";
const version = process.env.VERSION ?? "";
const targetDir = process.env.TARGET_DIR ?? "src-tauri/target";
const outDir = "release-artifact";

if (!os || !arch || !version) {
  console.error("::error::missing MATRIX_OS / MATRIX_ARCH / VERSION environment variables");
  process.exit(1);
}

// ---------------------------------------------------------------- helpers

function walkFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}

function setOutput(key, value) {
  console.log(`output ${key}=${value}`);
  const file = process.env.GITHUB_OUTPUT;
  if (file) fs.appendFileSync(file, `${key}=${value}\n`);
}

// ---------------------------------------------------------------- locate bundle dirs

// With --target, cargo puts artifacts in target/<triple>/release/; without it they land
// in target/release/. Probe both and use whichever one has a bundle.
const bundleRoots = [
  path.join(targetDir, target, "release", "bundle"),
  path.join(targetDir, "release", "bundle"),
].filter((p) => fs.existsSync(p));

if (bundleRoots.length === 0) {
  console.error(`::error::no bundle directory under ${targetDir}, the build probably failed.`);
  process.exit(1);
}

console.log("bundle directories:");
for (const root of bundleRoots) console.log(`  ${root}`);

// `nexa.app` is the macOS bundle directory; files inside it belong to the .app
// internals and must not be treated as standalone release assets (the real assets are
// .dmg and .app.tar.gz).
const isInsideAppBundle = (p) => /[\\/][^\\/]+\.app[\\/]/.test(p);

let bundleFiles = [];
for (const root of bundleRoots) {
  bundleFiles.push(...walkFiles(root));
}
bundleFiles = bundleFiles.filter((p) => !isInsideAppBundle(p));

if (bundleFiles.length === 0) {
  console.error("::error::the bundle directory contains no artifacts.");
  process.exit(1);
}

// ---------------------------------------------------------------- pick updater payload

const byName = (re) => bundleFiles.filter((p) => re.test(path.basename(p)));

// Only these file types belong in a Release. Without this filter, macOS jobs leak
// the DMG bundler's helper scripts (bundle_dmg.sh, template.applescript,
// eula-resources-template.xml, icon.icns) which Tauri writes next to the .dmg.
const PUBLISHABLE = [
  /\.dmg$/,
  /\.app\.tar\.gz(\.sig)?$/,
  /\.nsis\.zip(\.sig)?$/,
  /-setup\.exe(\.sig)?$/,
  /\.deb$/,
  /\.rpm$/,
  /\.AppImage$/,
  /\.AppImage\.tar\.gz(\.sig)?$/,
];
const isPublishable = (name) => PUBLISHABLE.some((re) => re.test(name));
const filteredOut = bundleFiles.filter((p) => !isPublishable(path.basename(p)));
if (filteredOut.length > 0) {
  console.log("Not publishing (not a release asset):");
  for (const p of filteredOut) console.log(`  ${path.basename(p)}`);
}

// Tauri v2 updater payloads per platform:
//   windows  the NSIS `*-setup.exe` is itself the update bundle (`*.nsis.zip` in
//            v1Compatible mode)
//   macos    `<productName>.app.tar.gz`
//   linux    `*.AppImage.tar.gz`
// Note: every regex is anchored with $ so `xxx.sig` is never matched by mistake.
let updaterSource = null;
if (os === "windows") {
  updaterSource = byName(/\.nsis\.zip$/)[0] ?? byName(/-setup\.exe$/)[0] ?? null;
} else if (os === "macos") {
  updaterSource = byName(/\.app\.tar\.gz$/)[0] ?? null;
} else if (os === "linux") {
  updaterSource = byName(/\.AppImage\.tar\.gz$/)[0] ?? null;
}

// Target file name:
//   - macOS must be renamed: the Tauri-generated `<productName>.app.tar.gz` has no
//     arch, so the amd64 and arm64 jobs would clash inside the same Release.
//   - Windows / Linux names already contain the arch (x64/arm64, amd64/arm64) and are
//     kept as-is, so the minisign signature does not need to be recomputed.
let updaterName = null;
let renamed = false;
if (updaterSource) {
  const original = path.basename(updaterSource);
  if (os === "macos") {
    const product = original.replace(/\.app\.tar\.gz$/, "");
    updaterName = `${product}_${version}_${arch}.app.tar.gz`;
    renamed = updaterName !== original;
  } else {
    updaterName = original;
  }
}

// ---------------------------------------------------------------- copy artifacts

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

const copied = new Map(); // destination file name -> source path
const skippedOriginals = new Set();

// After a rename, neither the original payload **nor its .sig** may be published:
// that signature was produced for the old file name, so keeping it would only let users
// download a bundle whose signature does not match.
const staleSources = new Set();
if (updaterSource && renamed) {
  staleSources.add(updaterSource);
  staleSources.add(`${updaterSource}.sig`);
}

for (const src of bundleFiles) {
  const name = path.basename(src);
  if (!isPublishable(name)) continue;
  if (staleSources.has(src)) {
    skippedOriginals.add(src);
    continue;
  }
  if (copied.has(name)) {
    console.warn(`::warning::overwriting artifact with the same name: ${name} (${copied.get(name)} -> ${src})`);
  }
  copied.set(name, src);
}

// The renamed updater payload and its .sig both land in the flat directory
if (updaterSource && renamed) {
  copied.set(updaterName, updaterSource);
  const sig = `${updaterSource}.sig`;
  if (fs.existsSync(sig)) copied.set(`${updaterName}.sig`, sig);
}

for (const [name, src] of copied) {
  fs.copyFileSync(src, path.join(outDir, name));
}

// ---------------------------------------------------------------- report

const written = fs.readdirSync(outDir).sort();
console.log(`\nStaged ${written.length} files into ${outDir}/:`);
for (const f of written) {
  const size = fs.statSync(path.join(outDir, f)).size;
  console.log(`  ${f}  (${(size / 1024 / 1024).toFixed(2)} MiB)`);
}

if (updaterSource) {
  const hasSig = fs.existsSync(path.join(outDir, `${updaterName}.sig`));
  console.log(`\nupdater payload: ${updaterName} (signature ${hasSig ? "generated" : "missing"})`);
  if (!hasSig) {
    console.log("::warning::updater signature file not found, latest.json will not be generated.");
  }
  setOutput("updater_file", hasSig ? updaterName : "");
} else {
  console.log("\nNo updater payload found for this platform (usually TAURI_SIGNING_PRIVATE_KEY is not configured).");
  setOutput("updater_file", "");
}

setOutput("renamed", renamed ? "true" : "false");

if (skippedOriginals.size > 0) {
  console.log(`\nRenamed (originals are no longer published on their own): ${[...skippedOriginals].map((p) => path.basename(p)).join(", ")}`);
}
