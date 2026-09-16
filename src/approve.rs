//! `ask` secrets are approved in the agent's own permission prompt. The hook that makes the agent
//! ask also issues a short-lived one-time grant; `run` refuses an `ask` secret without one, so an
//! agent can't skip the prompt by calling `hivelock run` in a form the prompt doesn't cover.
use crate::vault::{data_dir, now, private_open};
use std::io::Write;
use std::path::PathBuf;

// ponytail: the grant exists before the user answers; a denied call leaves it valid for this long
const GRANT_SECS: u64 = 120;

fn path(key: &str) -> PathBuf {
    let d = data_dir().join("grants");
    let _ = std::fs::create_dir_all(&d);
    d.join(key)
}

pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::getrandom(&mut b).expect("os rng");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Stable key for a wrapped command (`run --ask '<cmd>'` agents can't carry a nonce).
pub fn command_key(cmd: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in cmd.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    format!("cmd-{h:016x}")
}

pub fn issue(key: &str) {
    if let Ok(mut f) = private_open(&path(key), false) {
        let _ = f.write_all((now() + GRANT_SECS).to_string().as_bytes());
    }
}

pub fn issue_nonce() -> String {
    let n = format!("once-{}", random_hex(12));
    issue(&n);
    n
}

pub fn consume(key: &str) -> bool {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return false;
    }
    let p = path(key);
    let ok = std::fs::read_to_string(&p).ok().and_then(|t| t.trim().parse::<u64>().ok()).is_some_and(|exp| exp > now());
    let _ = std::fs::remove_file(p);
    ok
}

/// A real person at a terminal (agent tool shells have none).
pub fn human_terminal() -> bool {
    #[cfg(unix)]
    {
        std::fs::File::open("/dev/tty").is_ok()
    }
    #[cfg(not(unix))]
    {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal()
    }
}

/// `hivelock run --ask '<cmd>'` exactly (the form Codex rules and Cursor can match) → `<cmd>`.
pub fn parse_ask_wrap(cmd: &str) -> Option<&str> {
    let rest = cmd.trim();
    let rest = if let Some(r) = rest.strip_prefix("hivelock ") {
        r
    } else {
        let exe = std::env::current_exe().ok()?.display().to_string();
        rest.strip_prefix(&format!("\"{exe}\" ")).or(rest.strip_prefix(&format!("{exe} ")))?
    };
    let inner = rest.strip_prefix("run --ask '")?.strip_suffix('\'')?;
    (!inner.contains('\'')).then_some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_one_time() {
        let _env = crate::vault::TEST_ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HIVELOCK_HOME", std::env::temp_dir().join(format!("hl-approve-{}", std::process::id())));
        let n = issue_nonce();
        assert!(consume(&n));
        assert!(!consume(&n), "grant must not be reusable");
        assert!(!consume("../../etc/passwd"));
        let k = command_key("echo {{lock:X}}");
        issue(&k);
        assert!(consume(&command_key("echo {{lock:X}}")));
    }

    #[test]
    fn canonical_wrap_only() {
        assert_eq!(parse_ask_wrap("hivelock run --ask 'curl -H \"a: {{lock:X}}\" u'"), Some("curl -H \"a: {{lock:X}}\" u"));
        assert_eq!(parse_ask_wrap("FOO=1 hivelock run --ask 'echo {{lock:X}}'"), None);
        assert_eq!(parse_ask_wrap("hivelock run --ask 'a' && echo 'b'"), None);
        assert_eq!(parse_ask_wrap("cd /tmp && hivelock run --ask 'echo'"), None);
    }
}
