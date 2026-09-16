use crate::audit;
use crate::redact::Redactor;
use crate::vault::{home, Store};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn claude_dir() -> PathBuf {
    std::env::var_os("CLAUDE_CONFIG_DIR").map(PathBuf::from).unwrap_or_else(|| home().join(".claude"))
}

pub fn codex_dir() -> PathBuf {
    std::env::var_os("CODEX_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".codex"))
}

pub fn agent_dir(agent: &str) -> PathBuf {
    match agent {
        "claude" => claude_dir(),
        "codex" => codex_dir(),
        "copilot" => std::env::var_os("COPILOT_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".copilot")),
        "gemini" => std::env::var_os("GEMINI_CLI_HOME").map(|h| PathBuf::from(h).join(".gemini")).unwrap_or_else(|| home().join(".gemini")),
        other => home().join(format!(".{other}")),
    }
}

/// Where each agent persists prompts, tool output and pasted content.
pub fn targets(agent: &str) -> Vec<PathBuf> {
    let names: &[&str] = match agent {
        "claude" => &["projects", "history.jsonl", "paste-cache", "file-history", "shell-snapshots", "debug", "session-env"],
        "codex" => &["sessions", "archived_sessions", "history.jsonl", "session_index.jsonl", "shell_snapshots", "sqlite"],
        "gemini" => &["tmp", "history"],
        "qwen" => &["projects", "tmp", "history"],
        "copilot" => &["session-state", "session-store.db", "session-store.db-wal", "command-history-state.json", "logs"],
        "cursor" => &["projects", "chats"],
        _ => return Vec::new(),
    };
    let base = agent_dir(agent);
    names.iter().map(|n| base.join(n)).collect()
}

/// Small prompt-history file worth scrubbing right after a blocked prompt.
pub fn history_file(agent: &str) -> PathBuf {
    let f = match agent {
        "claude" | "codex" => "history.jsonl",
        "copilot" => "command-history-state.json",
        _ => return PathBuf::new(),
    };
    agent_dir(agent).join(f)
}

pub fn walk(p: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = std::fs::symlink_metadata(p) else { return };
    if meta.is_file() {
        out.push(p.to_path_buf());
    } else if meta.is_dir() {
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            walk(&e.path(), out);
        }
    }
}

pub fn scrub_paths(paths: &[PathBuf], agent: &str) -> Result<(usize, usize), String> {
    let store = Store::open()?;
    let red = Redactor::new(store.mask_pairs());
    let mut files = Vec::new();
    for p in paths {
        walk(p, &mut files);
    }
    let mut hits = 0;
    for f in &files {
        match red.scrub_file(f) {
            Ok(n) => hits += n,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => eprintln!("hivelock: skip {}: {e}", f.display()),
            Err(_) => {}
        }
    }
    if hits > 0 {
        audit::log("scrubbed", agent, "", "", 0);
    }
    Ok((files.len(), hits))
}

/// Fire-and-forget scrub of everything an agent stores, for agents whose hooks don't name the transcript.
pub fn spawn_delayed_agent(agent: &str, delay_ms: u64) {
    let Ok(exe) = std::env::current_exe() else { return };
    let _ = Command::new(exe)
        .args(["scrub", "--agent", agent, "--quiet", "--delay", &delay_ms.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

/// Fire-and-forget scrub after the agent has written the entry we just blocked/redacted.
pub fn spawn_delayed(files: &[&str], delay_ms: u64) {
    let files: Vec<&&str> = files.iter().filter(|f| !f.is_empty()).collect();
    let Ok(exe) = std::env::current_exe() else { return };
    if files.is_empty() {
        return;
    }
    let mut c = Command::new(exe);
    c.arg("scrub").arg("--delay").arg(delay_ms.to_string());
    for f in files {
        c.arg("--file").arg(f);
    }
    let _ = c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
}
