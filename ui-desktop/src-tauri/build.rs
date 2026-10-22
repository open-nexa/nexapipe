// Only referenced from the Windows block in `main()`. Without this gate the function is dead
// code on Linux/macOS, which CI's `clippy -D warnings` turns into a hard error.
#[cfg(target_os = "windows")]
fn target_arch_dir() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "amd64"
    }
    #[cfg(target_arch = "x86")]
    {
        "x86"
    }
    #[cfg(target_arch = "arm")]
    {
        "arm"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "arm",
        target_arch = "aarch64"
    )))]
    {
        "amd64"
    }
}

/// Fail the build if the three command lists are not aligned, the same shape of bug PR #100
/// fixed for `get_service_version`.
///
/// Tauri only consults its own access-control list once the application declares its own
/// permissions (see `permissions/app-commands.toml`), and the capability in
/// `capabilities/default.json` is what actually grants them to the webview. A command that lives
/// in `generate_handler!` but reaches neither of those is silently refused, and a command that
/// reaches the capability but is missing from the manifest is not something anyone can refer
/// to. Neither failure shows up until an invoke lands.
///
/// The check runs from `build.rs` so it covers every platform the workspace compiles for. It
/// reports *which* side is missing *which* entry — the same diff the reviewer laid out — and
/// exits non-zero. The set relationship is `generate_handler! ⊆ app-commands.toml ⊆ default.json`:
/// the manifest is what Tauri requires, and the capability is what is actually granted. The
/// capability is allowed to grow with framework-side entries (`core:default`, `os:default`, …),
/// so those are filtered out and never compared.
fn check_acl_alignment() {
    use std::collections::BTreeSet;
    use std::path::Path;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by Cargo during build script execution");
    let manifest_dir = Path::new(&manifest_dir);

    // 1. Pull the identifiers out of `tauri::generate_handler![ ... ]` in `src/lib.rs`.
    //    Stripped by hand rather than via regex so the `build-dependencies` list stays small;
    //    the only macro with this signature in the file is the one to find.
    let lib_rs_path = manifest_dir.join("src").join("lib.rs");
    let lib_rs = std::fs::read_to_string(&lib_rs_path).unwrap_or_else(|e| {
        panic!(
            "ACL alignment check could not read {}: {e}",
            lib_rs_path.display()
        )
    });
    let handler_marker = "tauri::generate_handler![";
    let handler_open = lib_rs.find(handler_marker).unwrap_or_else(|| {
        panic!(
            "ACL alignment check: {} does not call `tauri::generate_handler![ ... ]`",
            lib_rs_path.display()
        )
    }) + handler_marker.len();
    let handler_block = match lib_rs[handler_open..].find(']') {
        Some(end) => &lib_rs[handler_open..handler_open + end],
        None => panic!(
            "ACL alignment check: `tauri::generate_handler![` in {} has no matching `]`",
            lib_rs_path.display()
        ),
    };

    let mut registered: BTreeSet<String> = BTreeSet::new();
    for raw in handler_block.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        // `quit::finish_quit` -> `finish_quit`; bare identifiers go through unchanged.
        let bare = entry.rsplit("::").next().unwrap_or(entry);
        registered.insert(bare.to_string());
    }

    // 2. Read the per-command permissions from `permissions/app-commands.toml`. Each
    //    `[[permission]]` block carries `commands.allow = ["..."]`.
    let toml_path = manifest_dir.join("permissions").join("app-commands.toml");
    let toml_text = std::fs::read_to_string(&toml_path).unwrap_or_else(|e| {
        panic!(
            "ACL alignment check could not read {}: {e}",
            toml_path.display()
        )
    });
    let toml_value: toml::Value =
        toml::from_str(&toml_text).expect("ACL alignment check: parse app-commands.toml");
    let mut granted_in_manifest: BTreeSet<String> = BTreeSet::new();
    if let Some(perms) = toml_value.get("permission").and_then(|v| v.as_array()) {
        for perm in perms {
            let Some(cmd_list) = perm.get("commands").and_then(|c| c.get("allow")) else {
                continue;
            };
            let Some(commands) = cmd_list.as_array() else {
                continue;
            };
            for cmd in commands {
                if let Some(name) = cmd.as_str() {
                    granted_in_manifest.insert(name.to_string());
                }
            }
        }
    }

    // 3. Read the capability in `capabilities/default.json`. The list mixes our `allow-X`
    //    entries with framework identifiers like `core:default` — the framework ones are kept
    //    out of the comparison, and the `allow-` prefix is replaced by an underscore so the
    //    names line up with the manifest.
    let json_path = manifest_dir.join("capabilities").join("default.json");
    let json_text = std::fs::read_to_string(&json_path).unwrap_or_else(|e| {
        panic!(
            "ACL alignment check could not read {}: {e}",
            json_path.display()
        )
    });
    let json_value: serde_json::Value = serde_json::from_str(&json_text)
        .expect("ACL alignment check: parse capabilities/default.json");
    let mut granted_in_capability: BTreeSet<String> = BTreeSet::new();
    if let Some(perms) = json_value.get("permissions").and_then(|v| v.as_array()) {
        for entry in perms {
            let Some(raw) = entry.as_str() else { continue };
            // only our app commands carry the `allow-` prefix; framework entries don't.
            let Some(stripped) = raw.strip_prefix("allow-") else {
                continue;
            };
            granted_in_capability.insert(stripped.replace('-', "_"));
        }
    }

    // 4. Compare.
    let missing_from_manifest: Vec<&String> = registered.difference(&granted_in_manifest).collect();
    let missing_from_capability: Vec<&String> = granted_in_manifest
        .difference(&granted_in_capability)
        .collect();

    if missing_from_manifest.is_empty() && missing_from_capability.is_empty() {
        println!(
            "cargo:info=ACL alignment check passed: {} commands in lib.rs, {} granted in app-commands.toml, {} granted in capabilities/default.json",
            registered.len(),
            granted_in_manifest.len(),
            granted_in_capability.len()
        );
        return;
    }

    eprintln!(
        "\n[acl-check] ui-desktop/src-tauri command / ACL alignment failed.\n\
         \n\
         The check enforces `generate_handler! ⊆ permissions/app-commands.toml ⊆ capabilities/default.json`.\n\
         A command in the first list but not the second (or in the second but not the third) is\n\
         silently refused by the webview, the same class of bug PR #100 fixed.\n"
    );
    if !missing_from_manifest.is_empty() {
        eprintln!(
            "  commands in src/lib.rs::generate_handler! but missing from permissions/app-commands.toml:"
        );
        for name in &missing_from_manifest {
            eprintln!("    - {name}");
        }
    }
    if !missing_from_capability.is_empty() {
        eprintln!(
            "  entries in permissions/app-commands.toml but missing from capabilities/default.json:"
        );
        for name in &missing_from_capability {
            eprintln!("    - {name}");
        }
    }
    eprintln!();
    eprintln!("Fix: add a matching `[[permission]]` block in app-commands.toml, or include `allow-<name>` in capabilities/default.json, then rebuild.");
    std::process::exit(1);
}

/// Fail the build if the three lists of error codes disagree.
///
/// The codes are a contract between three places: the Rust side that raises
/// them (`src/error.rs`), the frontend list that recognises them
/// (`../src/api/errors.ts`), and the locale files that give them a message
/// (`../src/i18n/locales/*.json`). Each of the three was maintained by hand,
/// and they drifted: a code the Rust side raises that the frontend list does
/// not know is a failure the UI renders as "unknown", and a locale key with
/// no code behind it is a message no failure can ever show.
///
/// The check runs from `build.rs` so it covers every platform the workspace
/// compiles for, and it reports *which* side is missing *which* entry. The
/// relationship is `error.rs == errors.ts` and `error.rs == locales - {unknown}`:
/// `unknown` is the fallback the frontend shows for a failure it cannot name,
/// so it has no code on the Rust side.
fn check_error_code_alignment() {
    use std::collections::BTreeSet;
    use std::path::Path;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by Cargo during build script execution");
    let manifest_dir = Path::new(&manifest_dir);
    let frontend_dir = manifest_dir.join("..").join("src");

    // 1. The codes the Rust side raises.
    let error_rs_path = manifest_dir.join("src").join("error.rs");
    let error_rs = std::fs::read_to_string(&error_rs_path).unwrap_or_else(|e| {
        panic!(
            "error code check could not read {}: {e}",
            error_rs_path.display()
        )
    });
    let mut rust_codes = BTreeSet::new();
    for line in error_rs.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("pub const ") {
            continue;
        }
        // `pub const NAME: &str = "the.code";`
        let Some(open) = trimmed.find('"') else {
            continue;
        };
        let Some(close) = trimmed[open + 1..].find('"') else {
            continue;
        };
        rust_codes.insert(trimmed[open + 1..open + 1 + close].to_string());
    }

    // 2. The list the frontend recognises.
    let errors_ts_path = frontend_dir.join("api").join("errors.ts");
    let errors_ts = std::fs::read_to_string(&errors_ts_path).unwrap_or_else(|e| {
        panic!(
            "error code check could not read {}: {e}",
            errors_ts_path.display()
        )
    });
    let marker = "ERROR_CODES = [";
    let open = errors_ts.find(marker).unwrap_or_else(|| {
        panic!(
            "error code check: {} does not declare `ERROR_CODES = [ ... ]`",
            errors_ts_path.display()
        )
    }) + marker.len();
    let block = match errors_ts[open..].find(']') {
        Some(end) => &errors_ts[open..open + end],
        None => panic!(
            "error code check: `ERROR_CODES = [` in {} has no matching `]`",
            errors_ts_path.display()
        ),
    };
    // The list is one code per line, grouped by comments. The comments are
    // lines of their own, so the file is read a line at a time: a chunk split
    // on commas would carry the comment that introduces a group onto the
    // first code of it, and that code would be read as part of the comment.
    let mut ts_codes = BTreeSet::new();
    for line in block.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with("//") {
            continue;
        }
        let Some(value) = entry.strip_prefix('\'') else {
            continue;
        };
        let Some(end) = value.find('\'') else {
            continue;
        };
        ts_codes.insert(value[..end].to_string());
    }

    // 3. The messages the locale files give them. Each locale holds the same
    //    `error` object, keyed by the code's own shape: `error.proxy.no_nodes`.
    fn locale_codes(path: &Path) -> BTreeSet<String> {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("error code check could not read {}: {e}", path.display()));
        let value: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("error code check: parse {}: {e}", path.display()));
        let mut out = BTreeSet::new();
        fn walk(value: &serde_json::Value, prefix: &str, out: &mut BTreeSet<String>) {
            let Some(object) = value.as_object() else {
                return;
            };
            for (key, child) in object {
                let path = format!("{prefix}.{key}");
                if child.is_object() {
                    walk(child, &path, out);
                } else {
                    out.insert(path);
                }
            }
        }
        if let Some(error) = value.get("error") {
            walk(error, "error", &mut out);
        }
        out
    }

    let locales_dir = frontend_dir.join("i18n").join("locales");
    let en = locale_codes(&locales_dir.join("en.json"));
    let zh = locale_codes(&locales_dir.join("zh-CN.json"));

    // The frontend's fallback for a failure it cannot name has no code on the
    // Rust side, so it is the one entry allowed to be there alone.
    let mut en_expected = en.clone();
    en_expected.remove("error.unknown");
    let mut zh_expected = zh.clone();
    zh_expected.remove("error.unknown");

    let rust_as_locale: BTreeSet<String> = rust_codes
        .iter()
        .map(|code| format!("error.{code}"))
        .collect();

    // The frontend's files are outside this package, so cargo does not know
    // that a change to them has to run this script again. Without these lines
    // the check only ever sees the state of the frontend at the first build,
    // and a drift introduced afterwards reaches the next release unnoticed.
    for path in [
        &error_rs_path,
        &errors_ts_path,
        &locales_dir.join("en.json"),
        &locales_dir.join("zh-CN.json"),
    ] {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let mut problems: Vec<String> = Vec::new();

    let missing_in_ts: Vec<&String> = rust_codes.difference(&ts_codes).collect();
    let extra_in_ts: Vec<&String> = ts_codes.difference(&rust_codes).collect();
    if !missing_in_ts.is_empty() || !extra_in_ts.is_empty() {
        problems.push(format!(
            "src/api/errors.ts and src/error.rs disagree:\n  in error.rs but not in errors.ts: {missing_in_ts:?}\n  in errors.ts but not in error.rs: {extra_in_ts:?}"
        ));
    }

    for (name, locale) in [("en.json", &en_expected), ("zh-CN.json", &zh_expected)] {
        let missing: Vec<&String> = rust_as_locale.difference(locale).collect();
        let extra: Vec<&String> = locale.difference(&rust_as_locale).collect();
        if !missing.is_empty() || !extra.is_empty() {
            problems.push(format!(
                "src/i18n/locales/{name} and src/error.rs disagree:\n  in error.rs but not in {name}: {missing:?}\n  in {name} but not in error.rs: {extra:?}"
            ));
        }
    }

    if problems.is_empty() {
        println!(
            "cargo:info=error code check passed: {} codes, agreed by src/error.rs, src/api/errors.ts and both locale files",
            rust_codes.len()
        );
        return;
    }

    eprintln!(
        "\n[error-code-check] ui-desktop/src-tauri error code alignment failed.\n\
         \n\
         The check enforces `src/error.rs == src/api/errors.ts` and `src/error.rs == locales - {{unknown}}`.\n\
         A code the Rust side raises that the frontend does not know is a failure the UI renders as\n\
         \"unknown\", and a locale key with no code behind it is a message no failure can show.\n"
    );
    for problem in &problems {
        eprintln!("  {problem}");
    }
    eprintln!();
    eprintln!("Fix: add the code to src/error.rs, list it in src/api/errors.ts, and give it an `error.<code>` key in both locale files.");
    std::process::exit(1);
}

fn main() {
    // No custom app manifest: Tauri's default already requests `asInvoker`, which is what the
    // service flow depends on — the app runs as the invoking user and only `sc.exe` is
    // re-launched elevated. Supplying our own manifest replaces that default wholesale and has
    // broken the binary with side-by-side error 14001.
    tauri_build::build();
    check_acl_alignment();
    check_error_code_alignment();

    #[cfg(target_os = "windows")]
    {
        // Scoped to this block: everything below is Windows-only, so importing these at
        // file level makes them unused (and a hard error under `-D warnings`) on
        // Linux/macOS CI.
        use std::env;
        use std::fs;
        use std::path::Path;

        let arch_dir = target_arch_dir();
        let wintun_src = format!("wintun/bin/{}/wintun.dll", arch_dir);
        let out_dir = env::var("OUT_DIR").unwrap();
        // OUT_DIR = target/{profile}/build/{pkg}-{hash}/out; going up three levels reaches
        // target/{profile} (where the exe lives).
        // Note: going up only two levels yields target/{profile}/build, not the exe directory —
        // wintun-bindings' load_from_path("wintun.dll") relies on the Windows DLL search order
        // resolving to the exe directory.
        let profile_dir = Path::new(&out_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let build_dir = Path::new(&out_dir).parent().unwrap().parent().unwrap();

        let src_path = Path::new(&wintun_src);
        // 1) Copy next to the exe (target/{profile}/wintun.dll) — the "application directory"
        //    of the system DLL search, so LoadLibrary("wintun.dll") in the tun crate /
        //    wintun-bindings resolves to the signed file.
        let exe_dst = profile_dir.join("wintun.dll");
        // 2) Keep a copy under target/{profile}/build/ (compatibility with the old layout /
        //    WINTUN_PATH injection).
        let legacy_dst = build_dir
            .join("wintun")
            .join("bin")
            .join(arch_dir)
            .join("wintun.dll");

        if src_path.exists() {
            fs::create_dir_all(legacy_dst.parent().unwrap()).unwrap();
            if let Err(e) = fs::copy(src_path, &legacy_dst) {
                println!("cargo:warning=Failed to copy wintun.dll: {}", e);
            }
            // Copying next to the exe must succeed, otherwise the runtime signature check
            // takes the wrong path.
            match fs::copy(src_path, &exe_dst) {
                Ok(_) => {
                    println!("cargo:rustc-env=WINTUN_PATH={}", exe_dst.display());
                    println!(
                        "cargo:info=Copied wintun.dll next to exe: {}",
                        exe_dst.display()
                    );
                }
                Err(e) => println!("cargo:warning=Failed to copy wintun.dll next to exe: {}", e),
            }
        } else {
            println!("cargo:warning=wintun.dll not found at {}. Please download from https://www.wintun.net/ and place it in wintun/bin/{}/", src_path.display(), arch_dir);
        }
    }
}
