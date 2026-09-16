use crate::detect;
use crate::hook::AGENTS;
use crate::scrub::agent_dir;
use crate::vault::{data_dir, Store};
use serde_json::{json, Map, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

const TITLE_ENV: &str = "CLAUDE_CODE_DISABLE_TERMINAL_TITLE";

fn config_path(agent: &str) -> Result<PathBuf, String> {
    let dir = agent_dir(agent);
    Ok(match agent {
        "claude" | "gemini" | "qwen" => dir.join("settings.json"),
        "codex" | "cursor" => dir.join("hooks.json"),
        "copilot" => dir.join("hooks").join("hivelock.json"),
        _ => return Err(format!("unsupported agent {agent} (supported: {})", AGENTS.join(", "))),
    })
}

/// copilot and cursor list handlers directly under the event; the rest nest them in matcher groups
fn flat(agent: &str) -> bool {
    matches!(agent, "copilot" | "cursor")
}

/// (event, matcher, hivelock sub-event)
fn events(agent: &str) -> Vec<(&'static str, Option<&'static str>, &'static str)> {
    match agent {
        "gemini" => vec![
            ("BeforeAgent", None, "prompt"),
            ("SessionStart", None, "start"),
            ("SessionEnd", None, "end"),
            ("BeforeTool", Some("run_shell_command|read_file"), "pre"),
            ("AfterTool", None, "post"),
        ],
        "copilot" => vec![
            ("userPromptTransformed", None, "prompt"),
            ("sessionStart", None, "start"),
            ("sessionEnd", None, "end"),
            ("PreToolUse", Some("Bash|Read"), "pre"),
            ("PostToolUse", None, "post"),
        ],
        "cursor" => vec![
            ("beforeShellExecution", None, "shell"),
            ("beforeSubmitPrompt", None, "prompt"),
            ("sessionStart", None, "start"),
            ("sessionEnd", None, "end"),
            ("preToolUse", Some("Shell|Read"), "pre"),
            ("postToolUse", None, "post"),
        ],
        _ => vec![
            ("UserPromptSubmit", None, "prompt"),
            ("SessionStart", None, "start"),
            ("SessionEnd", None, "end"),
            (
                "PreToolUse",
                Some(match agent {
                    "codex" => "Bash",
                    "qwen" => "run_shell_command|read_file",
                    _ => "Bash|Read",
                }),
                "pre",
            ),
            ("PostToolUse", if agent == "qwen" { None } else { Some("*") }, "post"),
        ],
    }
}

fn handler(agent: &str, event: &str, sub: &str) -> Value {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "hivelock".into());
    let command = format!("\"{exe}\" hook {agent} {sub}");
    match agent {
        "copilot" => json!({"type": "command", "command": command, "timeoutSec": 30}),
        "cursor" => json!({"command": command}),
        "gemini" => json!({"type": "command", "name": format!("hivelock-{sub}"), "command": command, "timeout": 30000}),
        "codex" if event == "SessionEnd" => json!({"type": "command", "command": command, "timeout": 3}),
        _ => json!({"type": "command", "command": command, "timeout": 30}),
    }
}

fn handler_cmd(h: &Value) -> String {
    match h["command"].as_str() {
        Some(c) => format!("{c} "),
        None => format!(
            "{} {} ",
            h["exec"].as_str().unwrap_or(""),
            h["args"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ")).unwrap_or_default()
        ),
    }
}

fn ours(agent: &str, h: &Value) -> bool {
    let c = handler_cmd(h);
    c.contains("hivelock") && c.contains(&format!(" hook {agent} "))
}

fn read_json(p: &PathBuf) -> Result<Value, String> {
    match std::fs::read_to_string(p) {
        Ok(t) if !t.trim().is_empty() => serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display())),
        _ => Ok(json!({})),
    }
}

fn write_json(p: &PathBuf, v: &Value) -> Result<(), String> {
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let bak = p.with_extension("json.hivelock-bak");
    if p.exists() && !bak.exists() {
        std::fs::copy(p, &bak).map_err(|e| e.to_string())?;
    }
    let tmp = p.with_extension("json.hivelock-tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(v).unwrap() + "\n").map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, p).map_err(|e| e.to_string())
}

/// Drops every hivelock handler; removes groups/events left empty.
fn strip(agent: &str, hooks: &mut Map<String, Value>) {
    for groups in hooks.values_mut() {
        if let Some(arr) = groups.as_array_mut() {
            if flat(agent) {
                arr.retain(|h| !ours(agent, h));
                continue;
            }
            for g in arr.iter_mut() {
                if let Some(hs) = g["hooks"].as_array_mut() {
                    hs.retain(|h| !ours(agent, h));
                }
            }
            arr.retain(|g| g["hooks"].as_array().is_none_or(|h| !h.is_empty()));
        }
    }
    hooks.retain(|_, g| g.as_array().is_none_or(|a| !a.is_empty()));
}

/// Events (by hivelock sub-event) whose hivelock handler is present.
fn installed(agent: &str, cfg: &Value) -> Vec<&'static str> {
    events(agent)
        .into_iter()
        .filter(|(ev, _, sub)| {
            cfg["hooks"][*ev].as_array().is_some_and(|gs| {
                let handlers: Vec<Value> = if flat(agent) {
                    gs.clone()
                } else {
                    gs.iter().flat_map(|g| g["hooks"].as_array().cloned().unwrap_or_default()).collect()
                };
                handlers.iter().any(|h| ours(agent, h) && handler_cmd(h).contains(&format!(" {sub} ")))
            })
        })
        .map(|(_, _, sub)| sub)
        .collect()
}

fn state_path() -> PathBuf {
    data_dir().join("installed.json")
}

pub fn install(agent: &str) -> Result<(), String> {
    let path = config_path(agent)?;
    if Store::init()? {
        println!("created vault in {}", data_dir().display());
    }
    let mut cfg = read_json(&path)?;
    if !cfg.is_object() {
        return Err(format!("{} is not a JSON object", path.display()));
    }
    if flat(agent) {
        cfg["version"] = json!(1);
    }
    let hooks = cfg.as_object_mut().unwrap().entry("hooks").or_insert(json!({}));
    let hooks = hooks.as_object_mut().ok_or("`hooks` is not an object")?;
    strip(agent, hooks);
    for (event, matcher, sub) in events(agent) {
        let mut entry = if flat(agent) { handler(agent, event, sub) } else { json!({"hooks": [handler(agent, event, sub)]}) };
        if let Some(m) = matcher {
            entry["matcher"] = json!(m);
        }
        hooks.entry(event).or_insert(json!([])).as_array_mut().ok_or("hook event is not an array")?.push(entry);
    }
    if agent == "claude" {
        // title generation would send a blocked prompt to the model provider
        let env = cfg.as_object_mut().unwrap().entry("env").or_insert(json!({}));
        let env = env.as_object_mut().ok_or("`env` is not an object")?;
        if !env.contains_key(TITLE_ENV) {
            env.insert(TITLE_ENV.into(), json!("1"));
            let mut st = read_json(&state_path())?;
            st["claude_title_env"] = json!(true);
            write_json(&state_path(), &st)?;
        }
    }
    write_json(&path, &cfg)?;
    if agent == "codex" {
        // native Codex approval prompt for `ask` secrets (hook denies any other form)
        let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
        let rules = format!(
            "# managed by hivelock: prompt before injecting an `ask` secret\nprefix_rule(\n    pattern = [[\"hivelock\", {exe:?}], \"run\", \"--ask\"],\n    decision = \"prompt\",\n    justification = \"hivelock: this command uses a secret that needs your approval\",\n)\n"
        );
        let rules_path = agent_dir(agent).join("rules").join("hivelock.rules");
        std::fs::create_dir_all(rules_path.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&rules_path, rules).map_err(|e| e.to_string())?;
    }
    println!("installed hivelock hooks for {agent} in {}", path.display());
    match agent {
        "codex" => println!("next: open Codex and run /hooks to review and trust the hivelock hooks (Codex skips untrusted hooks)"),
        "qwen" => println!("note: qwen support is experimental (not verified against a live qwen-code)"),
        "cursor" => println!("note: cursor hooks can block pasted secrets and inject secrets, but cannot hide shell output from the model"),
        _ => println!("restart running {agent} sessions to load the hooks"),
    }
    Ok(())
}

pub fn uninstall(agent: &str) -> Result<(), String> {
    let path = config_path(agent)?;
    let mut cfg = read_json(&path)?;
    if let Some(hooks) = cfg.get_mut("hooks").and_then(Value::as_object_mut) {
        strip(agent, hooks);
        if hooks.is_empty() {
            cfg.as_object_mut().unwrap().remove("hooks");
        }
    }
    if agent == "claude" && read_json(&state_path())?["claude_title_env"] == json!(true) {
        if let Some(env) = cfg.get_mut("env").and_then(Value::as_object_mut) {
            env.remove(TITLE_ENV);
            if env.is_empty() {
                cfg.as_object_mut().unwrap().remove("env");
            }
        }
        let mut st = read_json(&state_path())?;
        st.as_object_mut().map(|o| o.remove("claude_title_env"));
        write_json(&state_path(), &st)?;
    }
    if agent == "copilot" && cfg.get("hooks").is_none() {
        let _ = std::fs::remove_file(&path); // our own file
        let _ = std::fs::remove_file(path.with_extension("json.hivelock-bak"));
    } else {
        write_json(&path, &cfg)?;
    }
    if agent == "codex" {
        let _ = std::fs::remove_file(agent_dir(agent).join("rules").join("hivelock.rules"));
    }
    println!("removed hivelock hooks for {agent} from {}", path.display());
    Ok(())
}

fn hook_call(home: &PathBuf, agent: &str, event: &str, input: &Value) -> (String, u128) {
    let t0 = Instant::now();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["hook", agent, event])
        .env("HIVELOCK_HOME", home)
        .env("HIVELOCK_NO_CLIPBOARD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return (String::new(), 0) };
    let _ = child.stdin.take().unwrap().write_all(input.to_string().as_bytes());
    let out = child.wait_with_output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    (out, t0.elapsed().as_millis())
}

pub fn doctor() -> Result<i32, String> {
    let mut fails = 0;
    let mut check = |ok: bool, msg: String| {
        println!("{} {msg}", if ok { "[ok]  " } else { "[FAIL]" });
        if !ok {
            fails += 1;
        }
    };

    match Store::open() {
        Ok(s) => check(true, format!("vault opens ({} secrets) at {}", s.live().count(), data_dir().display())),
        Err(e) => check(false, format!("vault: {e}")),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: PathBuf| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
        let (d, k) = (mode(data_dir()), mode(Store::key_path()));
        check(d == 0o700 && k == 0o600, format!("permissions dir {d:o} key {k:o} (want 700/600)"));
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
    let mut any_agent = false;
    for agent in AGENTS {
        let path = config_path(agent)?;
        let Ok(cfg) = read_json(&path) else { continue };
        let got = installed(agent, &cfg);
        if got.is_empty() {
            continue;
        }
        any_agent = true;
        let want = events(agent).len();
        check(got.len() == want, format!("{agent}: hooks installed {}/{want} in {}", got.len(), path.display()));
        let json_exe = serde_json::to_string(&exe).unwrap();
        check(cfg["hooks"].to_string().matches(json_exe.trim_matches('"')).count() >= got.len(), format!("{agent}: hook commands point at this binary ({exe})"));
        match *agent {
            "claude" => check(cfg["env"][TITLE_ENV] == json!("1"), format!("claude: {TITLE_ENV}=1 (stops title generation leaking blocked prompts)")),
            "codex" => println!("[info] codex: hook trust can't be verified from outside; confirm in Codex `/hooks`"),
            _ => {}
        }
    }

    // live self-test in a throwaway vault, never touching the real one
    let tmp = std::env::temp_dir().join(format!("hivelock-doctor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let token = detect::fake_token();
    let transcript = tmp.join("transcript.jsonl");
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    std::fs::write(&transcript, format!("{{\"content\":\"use {token} please\"}}\n")).map_err(|e| e.to_string())?;
    let (out, _) = hook_call(&tmp, "claude", "prompt", &json!({"prompt": format!("use {token} please"), "transcript_path": transcript, "cwd": "/"}));
    check(out.contains("\"block\"") && out.contains("{{lock:GITHUB_TOKEN}}") && !out.contains(&token), "self-test: pasted token blocked and locked".into());
    let (out, _) = hook_call(&tmp, "claude", "post", &json!({"tool_name": "Bash", "tool_response": {"stdout": format!("x {token}"), "stderr": ""}}));
    check(out.contains("[lock:GITHUB_TOKEN]") && !out.contains(&token), "self-test: tool output masked".into());
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let t = std::fs::read_to_string(&transcript).unwrap_or_default();
    check(!t.contains(&token) && t.contains("[lock:GITHUB_TOKEN]"), "self-test: transcript scrubbed in place".into());

    let mut times: Vec<u128> = (0..15).map(|_| hook_call(&tmp, "claude", "prompt", &json!({"prompt": "refactor the login handler please"})).1).collect();
    times.sort_unstable();
    let p50 = times[times.len() / 2];
    check(p50 < 15, format!("latency: no-secret prompt hook p50 {p50}ms (incl. process spawn)"));
    let _ = std::fs::remove_dir_all(&tmp);

    if !any_agent {
        println!("[info] no agent hooks installed yet: `hivelock install claude` or `hivelock install codex`");
    }
    Ok(if fails > 0 { 1 } else { 0 })
}
