use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader, Read},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Traffic {
    pub up: f64,
    pub down: f64,
}
pub fn parse_line(line: &str) -> Option<(u32, Traffic)> {
    let mut cols = line.rsplitn(3, '\t');
    let down = cols.next()?.trim().parse::<f64>().ok()?;
    let up = cols.next()?.trim().parse::<f64>().ok()?;
    if !down.is_finite() || !up.is_finite() || down < 0.0 || up < 0.0 {
        return None;
    }
    let mut identity = cols.next()?.rsplitn(3, '/');
    let _uid = identity.next()?.parse::<u32>().ok()?;
    let pid = identity.next()?.parse::<u32>().ok()?;
    Some((
        pid,
        Traffic {
            up: up * 1024.0,
            down: down * 1024.0,
        },
    ))
}
pub fn nethogs_path() -> Option<&'static str> {
    if crate::process::is_flatpak() {
        if Path::new("/run/host/root/usr/bin/nethogs").is_file() {
            return Some("/usr/bin/nethogs");
        }
        if Path::new("/run/host/root/usr/sbin/nethogs").is_file() {
            return Some("/usr/sbin/nethogs");
        }
    }
    ["/usr/sbin/nethogs", "/usr/bin/nethogs"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
}

pub fn nethogs_has_caps() -> bool {
    let path = match nethogs_path() {
        Some(p) => p,
        None => return false,
    };
    if crate::process::is_flatpak() {
        if let Ok(output) = Command::new("flatpak-spawn")
            .args(["--host", "getcap", path])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if text.contains("cap_net_raw") || text.contains("cap_net_admin") {
                    return true;
                }
            }
        }
        return false;
    }
    for bin in ["/usr/bin/getcap", "/usr/sbin/getcap", "getcap"] {
        if let Ok(output) = Command::new(bin).arg(path).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if text.contains("cap_net_raw") || text.contains("cap_net_admin") {
                    return true;
                }
            }
        }
    }
    false
}
#[derive(Default)]
pub struct Network {
    pub rows: HashMap<u32, Traffic>,
    pub updated: Option<Instant>,
    pub status: String,
    pub running: bool,
}
impl Network {
    pub fn fresh(&self) -> bool {
        self.running
            && self
                .updated
                .is_some_and(|t| t.elapsed() < Duration::from_secs(4))
    }
}
pub struct Capture {
    input: Option<ChildStdin>,
    child: Option<Child>,
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.input.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}
pub fn start(state: Arc<Mutex<Network>>) -> io::Result<Capture> {
    let n_path = nethogs_path().ok_or_else(|| {
        io::Error::other(
            "NetHogs is missing. Install it with: sudo dnf install nethogs (Fedora) or sudo apt install nethogs (Ubuntu).",
        )
    })?;

    let in_flatpak = crate::process::is_flatpak();
    let use_caps = nethogs_has_caps();
    let mut child = if in_flatpak {
        Command::new("flatpak-spawn")
            .args(["--host", n_path, "-t", "-d", "1", "-v", "0"])
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?
    } else if use_caps {
        Command::new(n_path)
            .args(["-t", "-d", "1", "-v", "0"])
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?
    } else {
        Command::new("/usr/bin/pkexec")
            .arg(std::env::current_exe()?)
            .arg("--collector")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?
    };
    let input = child.stdin.take();
    let output = child.stdout.take().unwrap();
    let errors = child.stderr.take().unwrap();
    {
        let mut s = state.lock().unwrap();
        s.running = true;
        s.status = if use_caps {
            "Live network • measured by NetHogs (direct)".into()
        } else {
            "Waiting for administrator authorization…".into()
        };
        s.updated = None;
        s.rows.clear();
    }
    let err = Arc::new(Mutex::new(String::new()));
    let e = err.clone();
    let error_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = errors.take(8192).read_to_string(&mut text);
        *e.lock().unwrap() = text;
    });
    thread::spawn(move || {
        let mut batch = HashMap::<u32, Traffic>::new();
        let mut started = false;
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if line.trim() == "Refreshing:" {
                if started {
                    let mut s = state.lock().unwrap();
                    s.rows = std::mem::take(&mut batch);
                    s.updated = Some(Instant::now());
                    s.status = "Live network • measured by NetHogs".into();
                }
                started = true;
            } else if let Some((pid, t)) = parse_line(&line) {
                let entry = batch.entry(pid).or_default();
                entry.up += t.up;
                entry.down += t.down;
            }
        }
        let _ = error_reader.join();
        let mut s = state.lock().unwrap();
        s.running = false;
        s.rows.clear();
        s.updated = None;
        let detail = err.lock().unwrap().clone();
        s.status = if detail.trim().is_empty() {
            "Network monitoring stopped or authorization was cancelled. Enable to retry.".into()
        } else {
            format!("Network monitoring stopped: {}", detail.trim())
        };
    });
    Ok(Capture {
        input,
        child: Some(child),
    })
}
// Only the collector is elevated. Closing the GUI's stdin pipe makes this
// helper kill and reap NetHogs, even while no network packets are arriving.
pub fn collector() -> io::Result<()> {
    let path = nethogs_path().ok_or_else(|| io::Error::other("Install NetHogs first"))?;
    let child = Arc::new(Mutex::new(
        Command::new(path)
            .args(["-t", "-d", "1", "-v", "0"])
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    ));
    let c = child.clone();
    thread::spawn(move || {
        let mut b = [0u8; 1];
        while let Ok(n) = io::stdin().read(&mut b) {
            if n == 0 {
                break;
            }
        }
        let _ = c.lock().unwrap().kill();
    });
    loop {
        if let Some(status) = child.lock().unwrap().try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err(io::Error::other(format!("NetHogs exited: {status}")));
        }
        thread::sleep(Duration::from_millis(100));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_and_units() {
        assert_eq!(
            parse_line("/opt/Browser Helper/chrome/123/1000\t1.5\t2.25"),
            Some((
                123,
                Traffic {
                    up: 1536.0,
                    down: 2304.0
                }
            ))
        );
    }
    #[test]
    fn reject_bad_samples() {
        for s in [
            "Refreshing:",
            "x/1/1\tNaN\t2",
            "x/1/1\t1\t-2",
            "x/no/1\t1\t2",
        ] {
            assert!(parse_line(s).is_none());
        }
    }
    #[test]
    fn stale_is_not_zero() {
        let s = Network {
            running: true,
            updated: Some(Instant::now() - Duration::from_secs(5)),
            ..Default::default()
        };
        assert!(!s.fresh());
    }
}
