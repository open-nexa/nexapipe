//! Temporary diagnostic: create a wintun adapter -> netsh configure 10.0.0.1 -> verify it is
//! bindable -> clean up.
//! Only used to confirm the root cause and the fix for the WSAEADDRNOTAVAIL (10049) DNS bind
//! failure in TUN mode.
//!
//! The whole thing depends on wintun.dll and netsh, i.e. Windows only. The real body lives in
//! the cfg-gated module below so that `cargo check --all-targets` still succeeds on
//! Linux/macOS, where tun::PlatformConfig has no wintun_file().

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    return windows_probe::run();

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("tun_probe: this diagnostic only runs on Windows (needs wintun.dll + netsh)");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows_probe {
    use std::net::UdpSocket;
    use std::path::PathBuf;
    use std::time::Duration;
    use tun::AbstractDevice;

    fn find_wintun() -> Option<PathBuf> {
        let exe_dir = std::env::current_exe()
            .ok()?
            .parent()
            .map(|p| p.to_path_buf())?;
        let arch = if cfg!(target_arch = "x86_64") { "amd64" } else { "x86" };
        [
            exe_dir.join("wintun.dll"),
            exe_dir.join("wintun").join("bin").join(arch).join("wintun.dll"),
            PathBuf::from(
                r"C:\Users\eason\rust\nexapipe\ui-desktop\src-tauri\target\debug\wintun.dll",
            ),
        ]
        .into_iter()
        .find(|p| p.exists())
    }

    fn bind_check(ip: &str) -> bool {
        UdpSocket::bind((ip, 0)).is_ok()
    }

    fn run_netsh(name: &str, args: &[&str]) -> std::io::Result<bool> {
        let mut cmd = std::process::Command::new("netsh");
        cmd.args(["interface", "ip", "set", "address", &format!("name={}", name)]);
        cmd.args(args);
        let out = cmd.output()?;
        println!(
            "  netsh {} -> success={} stdout=[{}] stderr=[{}]",
            args.join(" "),
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(out.status.success())
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let wt = find_wintun().ok_or("wintun.dll not found")?;
        println!("wintun.dll: {}", wt.display());

        let mut cfg = tun::Configuration::default();
        cfg.platform_config(|pc| {
            pc.wintun_file(wt.clone());
        });
        cfg.tun_name("nexa-tun-probe");
        cfg.mtu(1500);
        let dev = tun::create_as_async(&cfg)?;
        let name = dev.tun_name()?;
        println!("device ready: {} mtu={}", name, dev.mtu().unwrap_or(1500));

        // Scenario A: the old command (with the self-referencing gateway 10.0.0.1)
        println!("[A] with gateway (old command):");
        let _ = run_netsh(&name, &["static", "10.0.0.1", "255.255.255.0", "10.0.0.1"])?;
        std::thread::sleep(Duration::from_millis(300));
        println!("  bind 10.0.0.1:0 -> {}", bind_check("10.0.0.1"));
        println!(
            "  bind 10.0.0.1:53 -> {:?}",
            UdpSocket::bind("10.0.0.1:53").map(|_| "OK").map_err(|e| e.to_string())
        );

        // Scenario B: the new command (no gateway)
        println!("[B] without gateway (new command):");
        let _ = run_netsh(&name, &["static", "10.0.0.1", "255.255.255.0"])?;
        std::thread::sleep(Duration::from_millis(300));
        println!("  bind 10.0.0.1:0 -> {}", bind_check("10.0.0.1"));
        println!(
            "  bind 10.0.0.1:53 -> {:?}",
            UdpSocket::bind("10.0.0.1:53").map(|_| "OK").map_err(|e| e.to_string())
        );

        // Scenario C: retry semantics (5 consecutive set + bind checks, simulating the new configure_interface)
        println!("[C] retry loop (5x):");
        let mut ok = false;
        for attempt in 1..=5 {
            let _ = run_netsh(&name, &["static", "10.0.0.1", "255.255.255.0"])?;
            if bind_check("10.0.0.1") {
                println!("  attempt {}: 10.0.0.1 bindable", attempt);
                ok = true;
                break;
            }
            println!("  attempt {}: not bindable, sleep 500ms", attempt);
            std::thread::sleep(Duration::from_millis(500));
        }
        println!("[C] final bindable: {}", ok);

        println!("done, dropping device (adapter will be deleted)");
        drop(dev);
        std::thread::sleep(Duration::from_millis(800));
        Ok(())
    }
}
