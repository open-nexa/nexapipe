#!/usr/bin/env python3
"""Local self-test: validate YAML/JSON syntax and run the 4 scripts against fake bundles."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(r"C:\Users\eason\rust\nexapipe\ui-desktop")
NODE = r"C:\Users\eason\.workbuddy\binaries\node\versions\22.22.2-3\node.exe"
if not Path(NODE).exists():
    NODE = r"C:\Program Files\nodejs\node.exe"

failures = []


def check(label, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label}{'  ' + detail if detail else ''}")
    if not ok:
        failures.append(label)


# ---------------------------------------------------------------- 1. JSON syntax
for rel in ["src-tauri/tauri.conf.json", "src-tauri/capabilities/default.json", "package.json"]:
    p = ROOT / rel
    try:
        json.loads(p.read_text(encoding="utf-8"))
        check(f"JSON parses: {rel}", True)
    except Exception as e:  # noqa: BLE001
        check(f"JSON parses: {rel}", False, str(e))

# ---------------------------------------------------------------- 2. YAML syntax
yaml_path = ROOT / ".github" / "workflows" / "release.yml"
try:
    import yaml  # type: ignore

    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    check("YAML parses: release.yml", True)

    include = doc["jobs"]["build"]["strategy"]["matrix"]["include"]
    check("matrix covers 6 combinations", len(include) == 6, f"actual {len(include)}")
    got = sorted((m["os"], m["arch"]) for m in include)
    want = sorted(
        [("windows", "amd64"), ("windows", "arm64"), ("macos", "amd64"),
         ("macos", "arm64"), ("linux", "amd64"), ("linux", "arm64")]
    )
    check("platform/arch combinations correct", got == want, str(got))
    check("every combination has runner/target/bundles",
          all({"runner", "target", "bundles"} <= set(m) for m in include))

    # Step names and referenced scripts must exist
    steps = doc["jobs"]["build"]["steps"]

    # The dependency repo must be cloned anonymously: GITHUB_TOKEN only covers the repo
    # that triggered the workflow, so actions/checkout (which defaults to github.token)
    # cannot fetch a second one — it fails with "The process '.../git' failed with exit
    # code 1". open-nexa/nexapipe is public, so an unauthenticated clone is enough, and
    # NEXAPIPE_REPO_TOKEN (PAT) is only used when it is actually configured.
    # "clone" narrows it to the fetching step: the staging step below also mentions
    # both open-nexa/nexapipe and nexapipe-deps, in its error messages.
    dep_steps = [s for s in steps
                 if "clone" in (s.get("run") or "")
                 and "open-nexa/nexapipe" in (s.get("run") or "")]
    check("there is a step that fetches open-nexa/nexapipe", len(dep_steps) == 1, f"actual {len(dep_steps)}")
    if dep_steps:
        body = dep_steps[0].get("run") or ""
        check("that fetch pins the ref explicitly", "--branch" in body)
        check("that fetch lands in GITHUB_WORKSPACE/nexapipe-deps", "nexapipe-deps" in body)
        check("that fetch authenticates only when a PAT is configured", "DEP_TOKEN" in body)
        check("that fetch never puts the PAT in the URL", "x-access-token:@" not in body)
    check("workflow-level env defines NEXAPIPE_REF", "NEXAPIPE_REF" in (doc.get("env") or {}))

    # npm ci copies the platform-pruned lockfile verbatim and misses the optional native
    # packages on other platforms (npm/cli#4828), making the tauri CLI report
    # "Cannot find native binding".
    inst = [s for s in steps if s.get("name") == "Install frontend dependencies"]
    check("there is a frontend dependency install step", len(inst) == 1, f"actual {len(inst)}")
    if inst:
        body = inst[0].get("run", "") or ""
        check("dependency install does not use npm ci (lockfile lacks other platforms' native packages)", "npm ci" not in body)
        check("dependency install verifies the tauri CLI native binary", "npx tauri --version" in body)
    scripts = [
        ".github/scripts/ci-config.mjs",
        ".github/scripts/stage-artifact.mjs",
        ".github/scripts/latest-json.mjs",
    ]
    blob = yaml_path.read_text(encoding="utf-8")
    for s in scripts:
        check(f"workflow references {s}", s in blob)
        check(f"{s} exists", (ROOT / s).exists())
    check("assemble-release.mjs exists", (ROOT / ".github/scripts/assemble-release.mjs").exists())
    check("release job depends on build", doc["jobs"]["release"]["needs"] == "build")

    # The AppImage bundler copies /usr/bin/xdg-open into the image (shell-open API is
    # enabled via tauri-plugin-opener) and hard-fails when it does not exist.
    # ubuntu-22.04-arm does not ship xdg-utils, so it must be installed explicitly.
    apt = [s for s in steps if s.get("name") == "Install Linux dependencies"]
    check("there is a Linux dependency install step", len(apt) == 1, f"actual {len(apt)}")
    if apt:
        check("Linux deps include xdg-utils (AppImage bundling needs /usr/bin/xdg-open)",
              "xdg-utils" in (apt[0].get("run", "") or ""))

    # Blob storage uploads time out occasionally ("Unable to make request: ETIMEDOUT");
    # a second upload attempt with overwrite must be in place.
    retr = [s for s in steps if (s.get("if") or "").startswith("failure()")]
    check("there is a retry step gated on failure()", len(retr) == 1, f"actual {len(retr)}")
    if retr:
        w = retr[0]["with"]
        check("retry upload overwrites the partial artifact", bool(w.get("overwrite")))
        check("retry upload has the same artifact name as the first attempt",
              w.get("name") == "dist-${{ matrix.os }}-${{ matrix.arch }}")
except ImportError:
    print("SKIP  pyyaml is not installed, skipping deep YAML validation")
    raw = yaml_path.read_text(encoding="utf-8")
    check("release.yml is not empty", len(raw) > 200)
except Exception as e:  # noqa: BLE001
    check("YAML parses: release.yml", False, str(e))

# ---------------------------------------------------------------- 3. fake artifact smoke test
def run(cmd, cwd, env_extra):
    env = {**os.environ, **env_extra}
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


CASES = [
    # (os, arch, triple, bundle file names, expected updater name, expected rename)
    ("windows", "amd64", "x86_64-pc-windows-msvc", "nsis",
     ["nexa_0.2.0_x64-setup.exe", "nexa_0.2.0_x64-setup.exe.sig"],
     "nexa_0.2.0_x64-setup.exe", False),
    ("windows", "arm64", "aarch64-pc-windows-msvc", "nsis",
     ["nexa_0.2.0_arm64-setup.exe", "nexa_0.2.0_arm64-setup.exe.sig"],
     "nexa_0.2.0_arm64-setup.exe", False),
    ("macos", "amd64", "x86_64-apple-darwin", "dmg",
     ["nexa.app.tar.gz", "nexa.app.tar.gz.sig", "nexa_0.2.0_x64.dmg",
      # Tauri writes the DMG bundler's helper scripts next to the .dmg; they must
      # never reach the release (leaked into a real release before this filter).
      "bundle_dmg.sh", "template.applescript", "eula-resources-template.xml", "icon.icns"],
     "nexa_0.2.0_amd64.app.tar.gz", True),
    ("macos", "arm64", "aarch64-apple-darwin", "dmg",
     ["nexa.app.tar.gz", "nexa.app.tar.gz.sig", "nexa_0.2.0_aarch64.dmg"],
     "nexa_0.2.0_arm64.app.tar.gz", True),
    ("linux", "amd64", "x86_64-unknown-linux-gnu", "appimage",
     ["nexa_0.2.0_amd64.AppImage.tar.gz", "nexa_0.2.0_amd64.AppImage.tar.gz.sig",
      "nexa_0.2.0_amd64.AppImage", "nexa_0.2.0_amd64.deb"],
     "nexa_0.2.0_amd64.AppImage.tar.gz", False),
    ("linux", "arm64", "aarch64-unknown-linux-gnu", "appimage",
     ["nexa_0.2.0_arm64.AppImage.tar.gz", "nexa_0.2.0_arm64.AppImage.tar.gz.sig",
      "nexa_0.2.0_arm64.deb"],
     "nexa_0.2.0_arm64.AppImage.tar.gz", False),
]

staged_root = Path(tempfile.mkdtemp(prefix="tauri-ci-selftest-"))
platform_keys = set()

for osname, arch, triple, subdir, files, want_updater, want_renamed in CASES:
    work = staged_root / f"{osname}-{arch}"
    work.mkdir(parents=True)
    # stage-artifact.mjs appends to $GITHUB_OUTPUT; simulate it with a file
    gh_output = work / "github_output.txt"
    gh_output.write_text("", encoding="utf-8")

    bundle = work / "src-tauri" / "target" / triple / "release" / "bundle" / subdir
    bundle.mkdir(parents=True)
    for f in files:
        (bundle / f).write_text(f"payload-{f}", encoding="utf-8")
    # Files inside the macOS .app directory must not be treated as release assets
    if osname == "macos":
        inner = bundle.parent / "macos" / "nexa.app" / "Contents" / "MacOS"
        inner.mkdir(parents=True)
        (inner / "nexa").write_text("binary", encoding="utf-8")

    env = {
        "MATRIX_OS": osname,
        "MATRIX_ARCH": arch,
        "MATRIX_TARGET": triple,
        "TARGET_DIR": "src-tauri/target",
        "VERSION": "0.2.0",
        "GITHUB_OUTPUT": str(gh_output),
        "GITHUB_REPOSITORY": "open-nexa/nexa-desktop",
        "GITHUB_REF_NAME": "v0.2.0",
    }

    rc, out = run([NODE, str(ROOT / ".github/scripts/stage-artifact.mjs")], work, env)
    check(f"stage-artifact [{osname}-{arch}]", rc == 0, out.strip().splitlines()[-1] if out else "")

    staged = work / "release-artifact"
    outputs = dict(
        line.split("=", 1)
        for line in gh_output.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    check(f"updater_file [{osname}-{arch}]", outputs.get("updater_file") == want_updater,
          f"got={outputs.get('updater_file')}")
    check(f"renamed [{osname}-{arch}]", outputs.get("renamed") == str(want_renamed).lower(),
          f"got={outputs.get('renamed')}")
    check(f"renamed payload exists [{osname}-{arch}]", (staged / want_updater).exists())

    # Files inside .app must not be copied
    leaked = [p.name for p in staged.rglob("*") if p.is_file() and p.name == "nexa" and p.stat().st_size == 6]
    check(f"no .app internals leaked [{osname}-{arch}]", not leaked, str(leaked))
    # DMG bundler helper scripts must not be published either
    forbidden = [n for n in ("bundle_dmg.sh", "template.applescript",
                             "eula-resources-template.xml", "icon.icns")
                 if (staged / n).exists()]
    check(f"no dmg helper scripts leaked [{osname}-{arch}]", not forbidden, str(forbidden))
    # After a rename, neither the old payload nor the old .sig may remain
    if want_renamed:
        stale = [n for n in ("nexa.app.tar.gz", "nexa.app.tar.gz.sig") if (staged / n).exists()]
        check(f"no stale payload/signature left [{osname}-{arch}]", not stale, str(stale))

    env["UPDATER_FILE"] = outputs.get("updater_file", "")
    rc, out = run([NODE, str(ROOT / ".github/scripts/latest-json.mjs")], work, env)
    check(f"latest-json [{osname}-{arch}]", rc == 0, out.strip().splitlines()[0] if out else "")
    manifest_path = staged / f"latest-{osname}-{arch}.json"
    if manifest_path.exists():
        m = json.loads(manifest_path.read_text(encoding="utf-8"))
        key = next(iter(m["platforms"]))
        platform_keys.add(key)
        check(f"platform key [{osname}-{arch}]", re.match(r"^(windows|darwin|linux)-(x86_64|aarch64)$", key) is not None, key)
        check(f"manifest version [{osname}-{arch}]", m["version"] == "0.2.0")
        check(f"url points at this tag [{osname}-{arch}]",
              m["platforms"][key]["url"] == f"https://github.com/open-nexa/nexa-desktop/releases/download/v0.2.0/{want_updater}")
        check(f"signature is non-empty [{osname}-{arch}]", bool(m["platforms"][key]["signature"]))
    else:
        check(f"latest-{osname}-{arch}.json generated", False)

# ---------------------------------------------------------------- 4. assemble-release
dist = staged_root / "dist"
dist.mkdir()
for p in staged_root.glob("*/release-artifact/*"):
    shutil.copy2(p, dist / p.name)

rc, out = run([NODE, str(ROOT / ".github/scripts/assemble-release.mjs")],
              staged_root, {"DIST_DIR": "dist", "OUT_DIR": "release-artifacts"})
check("assemble-release", rc == 0, "")
print(out)

out_dir = staged_root / "release-artifacts"
latest = out_dir / "latest.json"
check("latest.json generated", latest.exists())
if latest.exists():
    m = json.loads(latest.read_text(encoding="utf-8"))
    got = set(m["platforms"])
    want = {"windows-x86_64", "windows-aarch64", "darwin-x86_64",
            "darwin-aarch64", "linux-x86_64", "linux-aarch64"}
    check("latest.json contains all 6 platforms", got == want, f"missing {want - got} / extra {got - want}")
    # Every url's asset name must really exist in the release directory
    names = {p.name for p in out_dir.iterdir()}
    missing = [k for k, v in m["platforms"].items() if v["url"].rsplit("/", 1)[-1] not in names]
    check("latest.json urls point at assets that exist", not missing, str(missing))
    # Critical: the two macOS architectures must not share a file name
    mac = [v["url"].rsplit("/", 1)[-1] for k, v in m["platforms"].items() if k.startswith("darwin")]
    check("macOS asset names do not clash across architectures", len(set(mac)) == 2, str(mac))

sums = out_dir / "SHA256SUMS.txt"
check("SHA256SUMS.txt generated", sums.exists())
if sums.exists():
    raw = sums.read_bytes()
    check("SHA256SUMS has no BOM", not raw.startswith(b"\xef\xbb\xbf"))
    check("SHA256SUMS uses LF", b"\r\n" not in raw)
    listed = {line.split("  ", 1)[1] for line in raw.decode().strip().split("\n")}
    actual = {p.name for p in out_dir.iterdir() if p.name != "SHA256SUMS.txt"}
    check("SHA256SUMS covers every asset", listed == actual, f"missing {actual - listed} / extra {listed - actual}")

# --------- 5. lockfile platform completeness (warning only, not counted as a failure)
# If the lockfile only contains the packages of the machine that generated it, npm ci
# misses the native binaries on other platforms.
# The workflow already heals itself with npm install, so this is only a hint — but a
# lockfile covering every platform would still be better.
lockfile = ROOT / "package-lock.json"
try:
    lock_pkgs = set((json.loads(lockfile.read_text(encoding="utf-8")).get("packages") or {}).keys())
    NEED = {
        "windows/amd64": "node_modules/@tauri-apps/cli-win32-x64-msvc",
        "windows/arm64": "node_modules/@tauri-apps/cli-win32-arm64-msvc",
        "macos/amd64": "node_modules/@tauri-apps/cli-darwin-x64",
        "macos/arm64": "node_modules/@tauri-apps/cli-darwin-arm64",
        "linux/amd64": "node_modules/@tauri-apps/cli-linux-x64-gnu",
        "linux/arm64": "node_modules/@tauri-apps/cli-linux-arm64-gnu",
    }
    missing_cli = [k for k, v in NEED.items() if v not in lock_pkgs]
    if missing_cli:
        print(f"WARN  package-lock.json is missing tauri CLI native packages for: {missing_cli}")
        print("      npm ci will report Cannot find native binding on those platforms (npm/cli#4828).")
        print("      The workflow heals itself with npm install; for a real fix, regenerate a lockfile that covers every platform.")
    else:
        print("PASS  package-lock.json contains tauri CLI native packages for all 6 platforms")
except Exception as e:  # noqa: BLE001
    print(f"WARN  cannot check package-lock.json: {e}")

shutil.rmtree(staged_root, ignore_errors=True)

# --------- 6. dependency branch self-check (using the local nexapipe clone)
# The branch that NEXAPIPE_REF points at must really contain crates/, otherwise CI
# still dies at the cp step. This validates it offline against the local clone, so a
# branch switch shows up immediately.
NEXAPIPE_LOCAL = Path(r"C:\Users\eason\rust\nexapipe")
if not NEXAPIPE_LOCAL.is_dir():
    print(f"SKIP  local clone not found, skipping dependency branch check: {NEXAPIPE_LOCAL}")
else:
    raw_wf = yaml_path.read_text(encoding="utf-8")
    m = re.search(r"NEXAPIPE_REF:\s*\$\{\{\s*vars\.NEXAPIPE_REF\s*\|\|\s*'([^']+)'", raw_wf)
    default_ref = m.group(1) if m else None
    check("can parse the NEXAPIPE_REF default from the workflow", bool(default_ref), f"ref={default_ref!r}")

    resolved = None
    for cand in filter(None, [default_ref, f"origin/{default_ref}" if default_ref else None]):
        rc, out = run(["git", "-C", str(NEXAPIPE_LOCAL), "ls-tree", "--name-only", cand],
                      str(NEXAPIPE_LOCAL), {})
        if rc == 0:
            resolved = (cand, out.split())
            break
    if resolved is None:
        check(f"local clone can resolve ref: {default_ref}", False)
    else:
        refname, names = resolved
        check(f"ref '{refname}' has crates/ at the top level", "crates" in names, f"top level: {names}")
        if "crates" in names:
            rc, out = run(["git", "-C", str(NEXAPIPE_LOCAL), "ls-tree", "--name-only",
                           f"{refname}:crates"], str(NEXAPIPE_LOCAL), {})
            check(f"ref '{refname}' crates/ contains nexapipe-client", "nexapipe-client" in out.split(),
                  f"actual {out.split()}")

print("\n" + ("=" * 60))
print(f"all passed {len(failures) == 0}" + ("" if not failures else f"  failures: {failures}"))
sys.exit(0 if not failures else 1)
