use std::{
    collections::HashMap,
    fs, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    time::Instant,
};

pub fn is_flatpak() -> bool {
    Path::new("/.flatpak-info").exists()
}

pub fn proc_dir() -> &'static str {
    if is_flatpak() && Path::new("/run/host/root/proc").is_dir() {
        "/run/host/root/proc"
    } else {
        "/proc"
    }
}
#[derive(Clone, Debug, Default)]
pub struct Process {
    pub pid: u32,
    pub parent: u32,
    pub start: u64,
    pub name: String,
    pub command: String,
    pub exe: String,
    pub uid: u32,
    pub memory: u64,
    pub cpu: f64,
    pub read: f64,
    pub write: f64,
    ticks: u64,
    pub io: Option<(u64, u64)>,
    pub is_app: bool,
}

pub fn is_application(name: &str, exe: &str, cgroup: &str, uid: u32) -> bool {
    if uid < 1000 {
        return false;
    }
    if matches!(
        name,
        "system-monitor"
            | "chrome"
            | "google-chrome"
            | "chromium"
            | "firefox"
            | "brave"
            | "antigravity-ide"
            | "agy"
            | "code"
            | "ChatGPT"
            | "slack"
            | "discord"
            | "telegram-desktop"
            | "spotify"
            | "ptyxis"
            | "gnome-terminal"
            | "alacritty"
            | "kitty"
            | "wezterm"
            | "nautilus"
            | "gedit"
            | "vlc"
            | "gimp"
            | "steam"
    ) {
        return true;
    }
    if exe.starts_with("/usr/libexec/")
        || exe.starts_with("/usr/lib/systemd/")
        || name.ends_with("-daemon")
        || name.ends_with("d")
        || name.starts_with("at-spi")
        || name.starts_with("gsd-")
        || name.starts_with("gnome-session")
        || name.starts_with("pipewire")
        || name.starts_with("wireplumber")
        || name.starts_with("xdg-")
    {
        return false;
    }
    cgroup.contains("app.slice")
}
pub fn parse_stat(text: &str) -> Option<(String, u32, u64, u64, u64)> {
    let left = text.find('(')?;
    let right = text.rfind(')')?;
    let f: Vec<_> = text.get(right + 2..)?.split_whitespace().collect();
    Some((
        text[left + 1..right].into(),
        f.get(1)?.parse().ok()?,
        f.get(19)?.parse().ok()?,
        f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?,
        f.get(21)?.parse::<i64>().ok()?.max(0) as u64,
    ))
}
pub fn read_process(pid: u32) -> Option<Process> {
    let p_dir = proc_dir();
    let base = format!("{p_dir}/{pid}");
    let (name, parent, start, ticks, rss) =
        parse_stat(&fs::read_to_string(format!("{base}/stat")).ok()?)?;
    let status = fs::read_to_string(format!("{base}/status")).ok()?;
    let uid = status.lines().find_map(|l| {
        l.strip_prefix("Uid:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })?;
    let command: String = fs::read(format!("{base}/cmdline"))
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().into())
        .unwrap_or_default();
    let exe = fs::read_link(format!("{base}/exe"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| {
            // When running in Flatpak sandbox, host symlinks under /proc/*/exe may be unreadable.
            // Fallback to the first token of the command line.
            command
                .split_whitespace()
                .next()
                .unwrap_or("Unavailable")
                .to_string()
        });
    let io = fs::read_to_string(format!("{base}/io")).ok().and_then(|s| {
        let get = |key: &str| {
            s.lines()
                .find_map(|l| l.strip_prefix(key)?.trim().parse::<u64>().ok())
        };
        Some((get("read_bytes:")?, get("write_bytes:")?))
    });
    let cgroup = fs::read_to_string(format!("{base}/cgroup")).unwrap_or_default();
    let is_app = is_application(&name, &exe, &cgroup, uid);
    Some(Process {
        pid,
        parent,
        start,
        name,
        command,
        exe,
        uid,
        memory: rss * unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64,
        ticks,
        io,
        is_app,
        ..Default::default()
    })
}
#[derive(Clone, Debug, Default)]
pub struct FileSystemInfo {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total: u64,
    pub free: u64,
    pub avail: u64,
    pub used: u64,
    pub used_percent: f64,
}

pub fn read_filesystems() -> Vec<FileSystemInfo> {
    use std::ffi::CString;
    let mut list = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let is_flatpak = std::path::Path::new("/.flatpak-info").exists()
        || std::path::Path::new("/run/host/root").exists();

    // In a Flatpak sandbox with --filesystem=host:ro, the host filesystem is mounted at /run/host/root.
    // Reading /proc/mounts inside the sandbox exposes thousands of Flatpak internal bind-mounts
    // (/usr, /app, /etc/machine-id, /etc/ld.so.conf, etc.).
    // By parsing /proc/self/mountinfo, we can extract the genuine host mount entries.
    if is_flatpak {
        if let Ok(s) = fs::read_to_string("/proc/self/mountinfo") {
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // mountinfo format:
                // 0: id, 1: parent_id, 2: major:minor, 3: root, 4: mount_point, ... - fs_type mount_source
                let Some(sep_idx) = parts.iter().position(|&p| p == "-") else {
                    continue;
                };
                if parts.len() < sep_idx + 3 || sep_idx < 5 {
                    continue;
                }
                let container_mount = parts[4];
                let fs_type = parts[sep_idx + 1];
                let dev = parts[sep_idx + 2];

                // We only care about host mounts (/run/host/root...) or physical block devices
                if !dev.starts_with("/dev/") {
                    continue;
                }
                if !container_mount.starts_with("/run/host/root") {
                    continue;
                }

                // Map `/run/host/root` -> `/` and `/run/host/root/home` -> `/home`
                let host_mount_point = if container_mount == "/run/host/root" {
                    "/".to_string()
                } else {
                    container_mount.strip_prefix("/run/host/root").unwrap_or(container_mount).to_string()
                };

                // Skip internal host runtime / container bind mounts
                if host_mount_point.starts_with("/var/lib/docker")
                    || host_mount_point.starts_with("/var/lib/containerd")
                    || host_mount_point.starts_with("/run/")
                    || host_mount_point.starts_with("/dev/")
                    || host_mount_point.starts_with("/proc/")
                    || host_mount_point.starts_with("/sys/")
                {
                    continue;
                }

                if !seen.insert(host_mount_point.clone()) {
                    continue;
                }

                let Ok(c_path) = CString::new(container_mount) else {
                    continue;
                };

                unsafe {
                    let mut stat: libc::statvfs = std::mem::zeroed();
                    if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                        let frsize = stat.f_frsize as u64;
                        let total = frsize * stat.f_blocks as u64;
                        let free = frsize * stat.f_bfree as u64;
                        let avail = frsize * stat.f_bavail as u64;
                        let used = total.saturating_sub(free);
                        let used_percent = if total > 0 {
                            (used as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
                        } else {
                            0.0
                        };
                        list.push(FileSystemInfo {
                            device: dev.into(),
                            mount_point: host_mount_point,
                            fs_type: fs_type.into(),
                            total,
                            free,
                            avail,
                            used,
                            used_percent,
                        });
                    }
                }
            }
        }
    }

    // Fallback or native host mode: read /proc/mounts
    if list.is_empty() {
        let Ok(s) = fs::read_to_string("/proc/mounts") else {
            return list;
        };
        for line in s.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let dev = parts[0];
            let mount_point = parts[1];
            let fs_type = parts[2];
            if !dev.starts_with("/dev/") {
                continue;
            }
            // Skip common sandbox/bind mounts if running outside or in other container
            if mount_point.starts_with("/etc/")
                || mount_point.starts_with("/usr/")
                || mount_point.starts_with("/app")
            {
                continue;
            }
            if !seen.insert(mount_point.to_string()) {
                continue;
            }
            let Ok(c_path) = CString::new(mount_point) else {
                continue;
            };
            unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                    let frsize = stat.f_frsize as u64;
                    let total = frsize * stat.f_blocks as u64;
                    let free = frsize * stat.f_bfree as u64;
                    let avail = frsize * stat.f_bavail as u64;
                    let used = total.saturating_sub(free);
                    let used_percent = if total > 0 {
                        (used as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
                    } else {
                        0.0
                    };
                    list.push(FileSystemInfo {
                        device: dev.into(),
                        mount_point: mount_point.into(),
                        fs_type: fs_type.into(),
                        total,
                        free,
                        avail,
                        used,
                        used_percent,
                    });
                }
            }
        }
    }

    list
}

#[derive(Default)]
pub struct Sampler {
    previous: HashMap<u32, Process>,
    at: Option<Instant>,
    net: Option<(u64, u64)>,
    cpu: Option<(u64, u64)>,
    core_cpu: Vec<(u64, u64)>,
    disk: Option<(u64, u64)>,
}
#[derive(Default, Clone)]
pub struct Snapshot {
    pub processes: Vec<Process>,
    pub down: f64,
    pub up: f64,
    pub cpu: f64,
    pub memory: String,
    pub cpu_cores: Vec<f64>,
    pub memory_used: u64,
    pub memory_total: u64,
    pub memory_cached: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub net_rx_total: u64,
    pub net_tx_total: u64,
    pub disk_read_rate: f64,
    pub disk_write_rate: f64,
    pub disk_read_total: u64,
    pub disk_write_total: u64,
    pub filesystems: Vec<FileSystemInfo>,
}
impl Sampler {
    pub fn sample(&mut self) -> Snapshot {
        let now = Instant::now();
        let dt = self
            .at
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(1.0)
            .max(0.001);
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
        let mut next = HashMap::new();
        let p_dir = proc_dir();
        if let Ok(entries) = fs::read_dir(p_dir) {
            for e in entries.flatten() {
                let Some(pid) = e.file_name().to_str().and_then(|s| s.parse().ok()) else {
                    continue;
                };
                let Some(mut p) = read_process(pid) else {
                    continue;
                };
                if let Some(old) = self.previous.get(&pid).filter(|o| o.start == p.start) {
                    p.cpu = p.ticks.saturating_sub(old.ticks) as f64 / hz / dt * 100.0;
                    if let (Some((r, w)), Some((or, ow))) = (p.io, old.io) {
                        p.read = r.saturating_sub(or) as f64 / dt;
                        p.write = w.saturating_sub(ow) as f64 / dt;
                    }
                }
                next.insert(pid, p);
            }
        }
        let mut out = Snapshot::default();
        if let Ok(s) = fs::read_to_string(format!("{p_dir}/net/dev")) {
            let (mut rx, mut tx) = (0u64, 0u64);
            for l in s.lines().skip(2) {
                if let Some((name, vals)) = l.split_once(':') {
                    if name.trim() == "lo" {
                        continue;
                    }
                    let v: Vec<u64> = vals
                        .split_whitespace()
                        .filter_map(|v| v.parse().ok())
                        .collect();
                    if v.len() > 8 {
                        rx += v[0];
                        tx += v[8];
                    }
                }
            }
            out.net_rx_total = rx;
            out.net_tx_total = tx;
            if let Some((r, t)) = self.net {
                out.down = rx.saturating_sub(r) as f64 / dt;
                out.up = tx.saturating_sub(t) as f64 / dt;
            }
            self.net = Some((rx, tx));
        }
        if let Ok(s) = fs::read_to_string(format!("{p_dir}/stat")) {
            let mut lines = s.lines();
            if let Some(first) = lines.next() {
                let v: Vec<u64> = first
                    .split_whitespace()
                    .skip(1)
                    .take(8)
                    .filter_map(|v| v.parse().ok())
                    .collect();
                if v.len() >= 5 {
                    let total = v.iter().sum::<u64>();
                    let idle = v[3] + v[4];
                    if let Some((t, i)) = self.cpu {
                        let d = total.saturating_sub(t);
                        if d > 0 {
                            out.cpu = 100.0 * (1.0 - idle.saturating_sub(i) as f64 / d as f64);
                        }
                    }
                    self.cpu = Some((total, idle));
                }
            }
            let mut next_core_cpu = Vec::new();
            for l in lines {
                let mut words = l.split_whitespace();
                let Some(name) = words.next() else { continue; };
                if !name.starts_with("cpu") || !name[3..].chars().all(|c| c.is_ascii_digit()) {
                    break;
                }
                let v: Vec<u64> = words.take(8).filter_map(|v| v.parse().ok()).collect();
                if v.len() >= 5 {
                    let total = v.iter().sum::<u64>();
                    let idle = v[3] + v[4];
                    let core_idx = next_core_cpu.len();
                    let pct = if let Some(&(t, i)) = self.core_cpu.get(core_idx) {
                        let d = total.saturating_sub(t);
                        if d > 0 {
                            (100.0 * (1.0 - idle.saturating_sub(i) as f64 / d as f64)).clamp(0.0, 100.0)
                        } else {
                            0.0
                        }
                    } else {
                        0.0
                    };
                    out.cpu_cores.push(pct);
                    next_core_cpu.push((total, idle));
                }
            }
            self.core_cpu = next_core_cpu;
        }
        if let Ok(s) = fs::read_to_string(format!("{p_dir}/diskstats")) {
            let mut total_read_sectors = 0u64;
            let mut total_write_sectors = 0u64;
            for l in s.lines() {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() > 9 {
                    let dev = f[2];
                    let is_physical = (dev.starts_with("sd") && dev[2..].chars().all(|c| c.is_ascii_alphabetic()))
                        || (dev.starts_with("nvme") && dev.contains('n') && !dev.contains('p'))
                        || (dev.starts_with("vd") && dev[2..].chars().all(|c| c.is_ascii_alphabetic()))
                        || (dev.starts_with("mmcblk") && !dev.contains('p'));
                    if is_physical {
                        let r_sec: u64 = f[5].parse().unwrap_or(0);
                        let w_sec: u64 = f[9].parse().unwrap_or(0);
                        total_read_sectors += r_sec;
                        total_write_sectors += w_sec;
                    }
                }
            }
            let total_read_bytes = total_read_sectors * 512;
            let total_write_bytes = total_write_sectors * 512;
            out.disk_read_total = total_read_bytes;
            out.disk_write_total = total_write_bytes;
            if let Some((prev_r, prev_w)) = self.disk {
                out.disk_read_rate = (total_read_bytes.saturating_sub(prev_r) as f64) / dt;
                out.disk_write_rate = (total_write_bytes.saturating_sub(prev_w) as f64) / dt;
            }
            self.disk = Some((total_read_bytes, total_write_bytes));
        }
        if let Ok(s) = fs::read_to_string(format!("{p_dir}/meminfo")) {
            let get = |key: &str| {
                s.lines()
                    .find_map(|l| {
                        l.strip_prefix(key)?
                            .split_whitespace()
                            .next()?
                            .parse::<u64>()
                            .ok()
                    })
                    .unwrap_or(0)
                    * 1024
            };
            let total = get("MemTotal:");
            let used = total.saturating_sub(get("MemAvailable:"));
            let cached = get("Cached:") + get("Buffers:");
            let swap_total = get("SwapTotal:");
            let swap_used = swap_total.saturating_sub(get("SwapFree:"));
            out.memory_total = total;
            out.memory_used = used;
            out.memory_cached = cached;
            out.swap_total = swap_total;
            out.swap_used = swap_used;
            out.memory = format!(
                "{} / {}",
                crate::bytes(used as f64),
                crate::bytes(total as f64)
            );
        }
        out.filesystems = read_filesystems();
        out.processes = next.values().cloned().collect();
        self.previous = next;
        self.at = Some(now);
        out
    }
}
// A pidfd pins the process identity across the final check and signal.
pub fn end_process(pid: u32, start: u64, force: bool) -> io::Result<()> {
    if pid <= 1 || pid == std::process::id() {
        return Err(io::Error::other("This process is protected"));
    }

    let is_flatpak_app = is_flatpak();

    if is_flatpak_app {
        let p = read_process(pid).ok_or_else(|| io::Error::other("Process already exited"))?;
        if p.start != start {
            return Err(io::Error::other("Process changed; select it again"));
        }
        let sig = if force { "-9" } else { "-15" };
        let status = std::process::Command::new("flatpak-spawn")
            .args(["--host", "kill", sig, &pid.to_string()])
            .status()?;
        if status.success() {
            return Ok(());
        } else {
            return Err(io::Error::other("Failed to terminate host process"));
        }
    }

    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let p = read_process(pid).ok_or_else(|| io::Error::other("Process already exited"))?;
    if p.start != start {
        return Err(io::Error::other("Process changed; select it again"));
    }
    if p.uid != unsafe { libc::getuid() } {
        return Err(io::Error::other("Only your own processes can be ended"));
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            if force { libc::SIGKILL } else { libc::SIGTERM },
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stat_handles_parentheses() {
        let s = "123 (a (worker)) S 1 0 0 0 0 0 0 0 0 0 15 5 0 0 0 0 0 0 99 1000 3";
        assert_eq!(parse_stat(s), Some(("a (worker)".into(), 1, 99, 20, 3)));
    }
    #[test]
    fn samples_real_process() {
        let mut s = Sampler::default();
        assert!(
            s.sample()
                .processes
                .iter()
                .any(|p| p.pid == std::process::id())
        );
    }
    #[test]
    fn identity_guard_and_termination() {
        let mut c = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let p = read_process(c.id()).unwrap();
        assert!(end_process(p.pid, p.start + 1, false).is_err());
        assert!(c.try_wait().unwrap().is_none());
        end_process(p.pid, p.start, false).unwrap();
        assert!(!c.wait().unwrap().success());
    }
}
