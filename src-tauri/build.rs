use std::env;
use std::fs;
use std::path::Path;

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

fn main() {
    // No custom app manifest: Tauri's default already requests `asInvoker`, which is what the
    // service flow depends on — the app runs as the invoking user and only `sc.exe` is
    // re-launched elevated. Supplying our own manifest replaces that default wholesale and has
    // broken the binary with side-by-side error 14001.
    tauri_build::build();

    #[cfg(target_os = "windows")]
    {
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
