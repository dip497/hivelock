//! Agent hook adapters. Every agent is normalized into the same few decisions
//! (block prompt, deny/rewrite/ask tool call, mask output, add context); only the
//! JSON shapes differ.
use crate::audit;
use crate::detect::{self, Finding};
use crate::redact::Redactor;
use crate::run::{placeholder_names, placeholder_re};
use crate::scrub;
use crate::vault::{data_dir, Store};
use base64::Engine;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const AGENTS: &[&str] = &["claude", "codex", "gemini", "qwen", "copilot", "cursor"];

#[derive(Clone, Copy, PartialEq)]
enum Tool {
    Shell,
    Read,
    Other,
}

/// What an agent's hook payload means, independent of its JSON dialect.
struct Call<'a> {
    agent: &'a str,
    v: &'a Value,
    tool: Tool,
    tool_name: String,
    input: Value,
    cwd: PathBuf,
}

impl<'a> Call<'a> {
    fn new(agent: &'a str, v: &'a Value) -> Self {
        // copilot camelCase payloads use toolName/toolArgs; everyone else snake_case
        let tool_name = v["tool_name"].as_str().or(v["toolName"].as_str()).unwrap_or("").to_string();
        let mut input = if v["tool_input"].is_null() { v["toolArgs"].clone() } else { v["tool_input"].clone() };
        if let Some(s) = input.as_str() {
            input = serde_json::from_str(s).unwrap_or(Value::Null);
        }
        let tool = match tool_name.as_str() {
            "Bash" | "Shell" | "run_shell_command" | "shell" | "bash" | "powershell" => Tool::Shell,
            "Read" | "read_file" | "view" => Tool::Read,
            _ => Tool::Other,
        };
        let cwd = v["cwd"]
            .as_str()
            .or(v["workspace_roots"][0].as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
        Call { agent, v, tool, tool_name, input, cwd }
    }

    fn transcript(&self) -> &str {
        self.v["transcript_path"].as_str().unwrap_or("")
    }

    fn file_path(&self) -> Option<String> {
        ["file_path", "path", "absolute_path", "target_file"].iter().find_map(|k| self.input[*k].as_str()).map(str::to_string)
    }
}

pub fn cli_name() -> String {
    let on_path = std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| d.join("hivelock").is_file() || d.join("hivelock.exe").is_file())
    });
    if on_path {
        "hivelock".into()
    } else {
        std::env::current_exe().map(|p| format!("\"{}\"", p.display())).unwrap_or("hivelock".into())
    }
}

/// Agents whose hooks can safely rewrite a shell command (verified not to bypass approvals).
fn can_rewrite(agent: &str) -> bool {
    matches!(agent, "claude" | "gemini" | "copilot")
}

/// Agents with a native approval prompt hivelock can trigger (hook `ask`, Codex prompt rule, Cursor shell hook).
fn can_ask(agent: &str) -> bool {
    agent != "gemini"
}

fn hint(agent: &str, names: &[String]) -> String {
    let wrap = if can_rewrite(agent) {
        String::new()
    } else {
        format!(" Run such commands wrapped as: {} run '<command>'.", cli_name())
    };
    format!(
        "hivelock is active: secrets are referenced by name, never by value. Write {{{{lock:NAME}}}} inside shell commands; \
         the value is injected at run time and masked as [lock:NAME] in output.{wrap} Never ask the user to paste a secret; \
         if one is missing ask them to run `hivelock add NAME` in their terminal. Locked secrets are human-only. Available: {}",
        if names.is_empty() { "none yet".to_string() } else { names.join(", ") }
    )
}

pub fn hook(agent: &str, event: &str) -> i32 {
    if !AGENTS.contains(&agent) {
        eprintln!("hivelock: unknown agent {agent}");
        return 1;
    }
    let t0 = Instant::now();
    let mut raw = String::new();
    let _ = std::io::stdin().read_to_string(&mut raw);
    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    let call = Call::new(agent, &v);
    let out = match event {
        "prompt" => on_prompt(&call, t0),
        "pre" => on_pre(&call),
        "shell" => on_shell(&call),
        "post" => on_post(&call, t0),
        "start" => on_start(&call),
        "end" => {
            match call.transcript() {
                "" => scrub::spawn_delayed_agent(agent, 1000),
                t => scrub::spawn_delayed(&[t, &scrub::history_file(agent).to_string_lossy()], 1000),
            }
            None
        }
        _ => {
            eprintln!("hivelock: unknown hook event {event}");
            return 1;
        }
    };
    if let Some(o) = out {
        println!("{o}");
    }
    0
}

/// Findings in `text`: rule matches plus re-pasted known values (any encoding).
fn find_all(text: &str, store: Option<&Store>) -> Vec<Finding> {
    let mut findings = detect::detect(text);
    if let Some(s) = store {
        for (a, b, name) in Redactor::new(s.mask_pairs()).find(text.as_bytes()) {
            if !findings.iter().any(|f| a < f.end && f.start < b) {
                findings.push(Finding { start: a, end: b, value: String::new(), kind: "known".into(), name: name.into() });
            }
        }
    }
    findings.sort_by_key(|f| f.start);
    findings
}

/// Stores new findings (renaming them to their final vault names) and returns the masked text.
fn lock_findings(call: &Call, text: &str, findings: &mut [Finding]) -> Result<String, String> {
    let saved = Store::init().and_then(|_| Store::open_rw()).and_then(|mut s| {
        for f in findings.iter_mut().filter(|f| !f.value.is_empty()) {
            let (name, _) = s.add(&f.name, &f.value, &f.kind, "global", &format!("chat:{}", call.agent));
            f.name = name;
        }
        s.save()
    });
    let mut masked = text.to_string();
    for f in findings.iter().rev() {
        masked.replace_range(f.start..f.end, &format!("{{{{lock:{}}}}}", f.name));
    }
    saved.map(|_| masked)
}

fn on_prompt(call: &Call, t0: Instant) -> Option<Value> {
    let store = Store::open().ok();
    // copilot: rewrite the model-facing content instead of blocking (true masking)
    if call.agent == "copilot" {
        let text = call.v["transformedPrompt"].as_str().or(call.v["prompt"].as_str()).unwrap_or("");
        let mut findings = find_all(text, store.as_ref());
        if findings.is_empty() {
            return None;
        }
        let masked = lock_findings(call, text, &mut findings).ok()?;
        for f in &findings {
            audit::log("masked_prompt", call.agent, &f.name, "", t0.elapsed().as_millis());
        }
        // the displayed copy of the prompt is still stored raw; mask it once written
        scrub::spawn_delayed_agent(call.agent, 3000);
        return Some(json!({"modifiedTransformedPrompt": format!("{masked}\n\n[{}]", hint(call.agent, &[]))}));
    }

    let prompt = call.v["prompt"].as_str().unwrap_or("");
    if prompt.contains("!nolock") {
        return None;
    }
    let mut findings = find_all(prompt, store.as_ref());
    if findings.is_empty() {
        if placeholder_re().is_match(prompt) && call.agent != "cursor" {
            let names = store.map(|s| s.visible_names(&call.cwd)).unwrap_or_default();
            let event = if call.agent == "gemini" { "BeforeAgent" } else { "UserPromptSubmit" };
            return Some(json!({"hookSpecificOutput": {"hookEventName": event, "additionalContext": hint(call.agent, &names)}}));
        }
        return None;
    }

    let (mut rewritten, status) = match lock_findings(call, prompt, &mut findings) {
        Ok(m) => {
            let mut listed: Vec<String> = findings.iter().map(|f| format!("{} ({})", f.name, f.kind)).collect();
            listed.dedup();
            (m, format!("Locked: {}", listed.join(", ")))
        }
        Err(e) => (String::new(), format!("Secret NOT stored (vault error: {e}).")),
    };
    let copied = !rewritten.is_empty() && copy_to_clipboard(&rewritten);
    if rewritten.len() > 1500 {
        let mut cut = 1500;
        while !rewritten.is_char_boundary(cut) {
            cut -= 1;
        }
        rewritten.truncate(cut);
        rewritten.push_str(" …");
    }
    let ms = t0.elapsed().as_millis();
    for f in &findings {
        audit::log("blocked_prompt", call.agent, &f.name, "", ms);
    }
    scrub::spawn_delayed(&[call.transcript(), &scrub::history_file(call.agent).to_string_lossy()], 1500);
    let reason = format!(
        "hivelock: your message contained a secret, so it was NOT sent.\n{status}\n\nResend it with the placeholder{}:\n\n{rewritten}\n\n(Not a secret? Add !nolock to your message.)",
        if copied { " (already copied to your clipboard, just paste)" } else { "" }
    );
    Some(match call.agent {
        "gemini" => json!({"decision": "deny", "reason": reason}),
        "cursor" => json!({"continue": false, "user_message": reason}),
        _ => json!({"decision": "block", "reason": reason}),
    })
}

/// Masked prompt → clipboard, so resending is one paste. The secret itself never goes there.
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if std::env::var_os("HIVELOCK_NO_CLIPBOARD").is_some() {
        return false;
    }
    let tools: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else if cfg!(windows) {
        &[("clip.exe", &[])]
    } else if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"])]
    } else {
        &[("xclip", &["-selection", "clipboard"]), ("xsel", &["-b", "-i"])]
    };
    tools.iter().any(|(prog, args)| {
        let Ok(mut child) = Command::new(prog).args(*args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
        else {
            return false;
        };
        // wl-copy/xclip keep serving the selection in the background; don't wait on them
        child.stdin.take().is_some_and(|mut i| i.write_all(text.as_bytes()).is_ok())
    })
}

enum Verdict {
    Deny(String),
    Rewrite(String),
    Ask(String, String),
}

fn verdict_json(call: &Call, verdict: Verdict) -> Value {
    let (decision, reason, command) = match verdict {
        Verdict::Deny(r) => {
            audit::log("denied", call.agent, "", &call.tool_name, 0);
            ("deny", r, None)
        }
        Verdict::Rewrite(c) => ("allow", String::new(), Some(c)),
        Verdict::Ask(r, c) => {
            audit::log("asked", call.agent, "", &call.tool_name, 0);
            ("ask", r, Some(c))
        }
    };
    let updated = command.map(|c| {
        let mut u = call.input.clone();
        u["command"] = json!(c);
        u
    });
    match call.agent {
        "gemini" => match updated {
            Some(u) => json!({"hookSpecificOutput": {"hookEventName": "BeforeTool", "tool_input": u}}),
            None => json!({"decision": "deny", "reason": reason}),
        },
        "cursor" => json!({"permission": "deny", "agent_message": reason, "user_message": reason}),
        "copilot" => {
            let mut o = json!({});
            if decision != "allow" {
                o["permissionDecision"] = json!(decision);
                o["permissionDecisionReason"] = json!(reason);
            }
            if let Some(u) = updated {
                o["modifiedArgs"] = u;
            }
            o
        }
        _ => {
            let mut h = json!({"hookEventName": "PreToolUse"});
            if decision != "allow" {
                h["permissionDecision"] = json!(decision);
                h["permissionDecisionReason"] = json!(reason);
            }
            if let Some(u) = updated {
                h["updatedInput"] = u;
            }
            json!({"hookSpecificOutput": h})
        }
    }
}

fn is_env_name(n: &str) -> bool {
    (n == ".env" || n.starts_with(".env.")) && !["example", "sample", "template", "dist"].iter().any(|s| n.ends_with(s))
}

fn is_key_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    l.starts_with("id_rsa") && !l.ends_with(".pub")
        || ["id_ed25519", "id_ecdsa", "id_dsa"].contains(&l.as_str())
        || [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk"].iter().any(|e| l.ends_with(e))
        || l.ends_with(".json") && ["credential", "service-account", "service_account", "sa-key", "keyfile"].iter().any(|w| l.contains(w))
        || l == "kubeconfig"
}

/// Keys without a telling name (`deploy_key`): sniff the first bytes.
fn starts_with_pem(p: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 11];
    std::fs::File::open(p).and_then(|mut f| f.read_exact(&mut head)).is_ok() && &head == b"-----BEGIN "
}

/// Env files and key files a tool call is about to read.
fn sensitive_refs(call: &Call) -> Vec<PathBuf> {
    let cands: Vec<String> = match call.tool {
        Tool::Read => call.file_path().into_iter().collect(),
        Tool::Shell => call.input["command"]
            .as_str()
            .unwrap_or("")
            .split(|c: char| c.is_whitespace() || "'\"`;|&<>()=".contains(c))
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect(),
        Tool::Other => Vec::new(),
    };
    cands
        .into_iter()
        .map(|c| match c.strip_prefix("~/") {
            Some(rest) => crate::vault::home().join(rest),
            None => call.cwd.join(c),
        })
        .filter(|p| {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            p.metadata().is_ok_and(|m| m.is_file() && m.len() < 1 << 20) && (is_env_name(n) || is_key_name(n) || starts_with_pem(p))
        })
        .collect()
}

/// Deny reason if the file holds secrets the vault doesn't know yet.
fn unlocked_secrets(p: &Path, store: Option<&Store>) -> Option<String> {
    let bytes = std::fs::read(p).ok()?;
    let known = |val: &str| store.is_some_and(|s| s.live().any(|e| e.value == val));
    let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let what = if is_env_name(n) {
        let text = String::from_utf8_lossy(&bytes);
        let open: Vec<String> = detect::parse_env(&text)
            .into_iter()
            .filter(|(_, k, val)| detect::env_secretish(k, val) && !known(val))
            .map(|(_, k, _)| k)
            .collect();
        (!open.is_empty()).then(|| format!("unlocked secrets ({})", open.join(", ")))?
    } else {
        let value = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(e) => base64::engine::general_purpose::STANDARD.encode(e.as_bytes()),
        };
        let keyish = value.contains("PRIVATE KEY-----") || value.contains("\"private_key\"") || value.contains("client-key-data") || n.ends_with(".p12") || n.ends_with(".pfx") || n.ends_with(".jks") || n.ends_with(".keystore");
        (keyish && !known(&value)).then(|| "key material".to_string())?
    };
    Some(format!(
        "{} holds {what}. Ask the user to run `hivelock import {}` in their terminal; then use {{{{lock:NAME}}}} (for key files it becomes a temp file path).",
        p.display(),
        p.display()
    ))
}

fn on_pre(call: &Call) -> Option<Value> {
    let decide = |verdict| Some(verdict_json(call, verdict));
    let dd = data_dir();
    let dd_json = serde_json::to_string(&dd.to_string_lossy()).unwrap_or_default();
    if call.input.to_string().contains(dd_json.trim_matches('"')) {
        return decide(Verdict::Deny("hivelock vault files are off-limits to agents.".into()));
    }

    let store = Store::open().ok();
    if let Some(reason) = sensitive_refs(call).iter().find_map(|p| unlocked_secrets(p, store.as_ref())) {
        return decide(Verdict::Deny(reason));
    }

    if call.tool != Tool::Shell {
        return None;
    }
    let cmd = call.input["command"].as_str().unwrap_or("");
    let names = placeholder_names(cmd);
    if names.is_empty() {
        return None;
    }
    let Some(store) = store else {
        return decide(Verdict::Deny("hivelock is not initialized; ask the user to run `hivelock init`.".into()));
    };
    let mut ask = Vec::new();
    for n in &names {
        match store.resolve(n, &call.cwd) {
            None => {
                return decide(Verdict::Deny(format!(
                    "Unknown secret {{{{lock:{n}}}}}. Available: {}. Ask the user to run `hivelock add {n}` if it is missing.",
                    store.visible_names(&call.cwd).join(", ")
                )))
            }
            Some(e) if e.locked => {
                return decide(Verdict::Deny(format!(
                    "{{{{lock:{n}}}}} is locked (human only). Ask the user to run this command in their own terminal."
                )))
            }
            Some(e) if e.ask => ask.push(n.clone()),
            _ => {}
        }
    }
    let ask_list = ask.join(", ");
    if !ask.is_empty() {
        let mode = call.v["permission_mode"].as_str().unwrap_or("");
        if matches!(mode, "bypassPermissions" | "dontAsk") {
            return decide(Verdict::Deny(format!(
                "{ask_list} needs the user's approval on each use, but approval prompts are off in this session ({mode})."
            )));
        }
        if !can_ask(call.agent) {
            return decide(Verdict::Deny(format!(
                "{ask_list} needs the user's approval on each use and this agent has no approval prompt hivelock can trigger. Ask the user to run the command themselves."
            )));
        }
    }
    let wrapped_already = cmd.contains("hivelock") && cmd.contains(" run ");
    let reason = format!("hivelock: this command uses {ask_list}; approve to inject it for this one call.");

    if can_rewrite(call.agent) {
        if wrapped_already {
            if ask.is_empty() {
                return None; // `run` resolves placeholders itself
            }
            return decide(Verdict::Deny("Write the command with {{lock:NAME}} placeholders directly; hivelock wraps it itself.".into()));
        }
        let exe = std::env::current_exe().ok()?;
        let amp = if call.tool_name == "powershell" { "& " } else { "" };
        // the native prompt approves this exact call; `run` refuses the ask secret without this grant
        let grant = if ask.is_empty() { String::new() } else { format!(" --grant {}", crate::approve::issue_nonce()) };
        let wrapped = format!(
            "{amp}\"{}\" run --agent {}{grant} --b64 {}",
            exe.display(),
            call.agent,
            base64::engine::general_purpose::STANDARD.encode(cmd)
        );
        return decide(if ask.is_empty() { Verdict::Rewrite(wrapped) } else { Verdict::Ask(reason, wrapped) });
    }

    // no safe rewrite: the agent re-issues the command in a form that runs as-is
    if ask.is_empty() {
        if wrapped_already {
            return None;
        }
        return decide(Verdict::Deny(format!(
            "Secrets are injected by hivelock. Re-run the same command wrapped as: {} run '<command>' (keep the {{{{lock:NAME}}}} placeholders).",
            cli_name()
        )));
    }
    if call.agent == "codex" {
        if let Err(why) = codex_prompts(call.transcript()) {
            return decide(Verdict::Deny(format!("{ask_list} needs the user's approval on each use, but this Codex session won't show a prompt ({why}).")));
        }
    }
    let Some(inner) = crate::approve::parse_ask_wrap(cmd) else {
        return decide(Verdict::Deny(format!(
            "{ask_list} needs the user's approval. Re-run as exactly one command: {} run --ask '<command>' (no single quotes inside, keep the {{{{lock:NAME}}}} placeholders).",
            cli_name()
        )));
    };
    crate::approve::issue(&crate::approve::command_key(inner));
    match call.agent {
        "qwen" => decide(Verdict::Ask(reason, cmd.to_string())),
        // codex: the `hivelock run --ask` prefix rule makes Codex prompt; cursor: beforeShellExecution asks
        _ => None,
    }
}

/// Codex prompt rules only reach a person when approvals are interactive, reviewed by the user,
/// and a sandbox exists (full access has nothing to escalate from). Read from the session's
/// latest turn context; unreadable → fail closed.
fn codex_prompts(transcript: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(transcript).map_err(|_| "session settings unreadable".to_string())?;
    let ctx = text
        .lines()
        .rev()
        .filter(|l| l.contains("\"turn_context\""))
        .find_map(|l| serde_json::from_str::<Value>(l).ok().filter(|v| v["type"] == "turn_context"))
        .ok_or("session settings unreadable")?;
    let p = &ctx["payload"];
    let approval = p["approval_policy"].as_str().unwrap_or(if p["approval_policy"].is_object() { "granular" } else { "" });
    let sandbox = p["sandbox_policy"]["type"].as_str().unwrap_or("");
    let reviewer = p["approvals_reviewer"].as_str().unwrap_or("user");
    match (approval, sandbox, reviewer) {
        ("never", _, _) | ("", _, _) => Err(format!("approval policy {approval:?}")),
        (_, "danger-full-access", _) => Err("full-access sandbox".into()),
        (_, _, r) if r != "user" => Err(format!("approvals reviewed by {r}")),
        _ => Ok(()),
    }
}

/// Cursor `beforeShellExecution`: its native "ask" for `hivelock run --ask` commands.
fn on_shell(call: &Call) -> Option<Value> {
    let cmd = call.v["command"].as_str()?;
    crate::approve::parse_ask_wrap(cmd)?;
    let msg = format!("hivelock: this command uses {}; approve to inject it for this one call.", placeholder_names(cmd).join(", "));
    Some(json!({"permission": "ask", "user_message": msg, "agent_message": msg}))
}

fn strings_mut(v: &mut Value, f: &mut dyn FnMut(&mut String)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| strings_mut(x, f)),
        Value::Object(o) => o.values_mut().for_each(|x| strings_mut(x, f)),
        _ => {}
    }
}

/// Model-facing text of a tool result, for agents that replace output with a plain string.
fn result_text(resp: &Value) -> String {
    match resp {
        Value::String(s) => s.clone(),
        Value::Object(o) => {
            for k in ["llmContent", "text_result_for_llm", "textResultForLlm"] {
                if let Some(s) = o.get(k).and_then(Value::as_str) {
                    return s.to_string();
                }
            }
            let parts: Vec<&str> = ["stdout", "stderr", "output"]
                .iter()
                .filter_map(|k| o.get(*k).and_then(Value::as_str))
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() { resp.to_string() } else { parts.join("\n") }
        }
        other => other.to_string(),
    }
}

fn on_post(call: &Call, t0: Instant) -> Option<Value> {
    let v = call.v;
    let key = ["tool_response", "tool_result", "toolResult", "tool_output", "output"].into_iter().find(|k| !v[*k].is_null())?;
    let mut resp = v[key].clone();
    if !Store::initialized() {
        return None;
    }

    // capture secrets the tool surfaced (e.g. `cat config.yml`) before the model sees them
    let mut found: Vec<Finding> = Vec::new();
    strings_mut(&mut resp, &mut |s| {
        if s.len() <= 2 << 20 {
            found.extend(detect::detect(s));
        }
    });
    if !found.is_empty() {
        if let Ok(mut s) = Store::open_rw() {
            for f in &found {
                let (name, new) = s.add(&f.name, &f.value, &f.kind, "global", &format!("tool:{}:{}", call.agent, call.tool_name));
                if new {
                    audit::log("captured", call.agent, &name, &call.tool_name, 0);
                }
            }
            let _ = s.save();
        }
    }

    let store = Store::open().ok()?;
    let red = Redactor::new(store.mask_pairs());
    if red.is_empty() {
        return None;
    }
    let mut hits = 0;
    strings_mut(&mut resp, &mut |s| {
        if let Some(r) = red.redact(s) {
            *s = r;
            hits += 1;
        }
    });
    if hits == 0 {
        return None;
    }
    audit::log("redacted", call.agent, "", &call.tool_name, t0.elapsed().as_millis());
    scrub::spawn_delayed(&[call.transcript()], 1500);
    let text = result_text(&resp);
    match call.agent {
        "claude" => Some(json!({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": resp}})),
        "copilot" => Some(json!({"modifiedResult": {"resultType": "success", "textResultForLlm": text}})),
        "gemini" => Some(json!({"decision": "deny", "reason": text})),
        // ponytail: cursor can only replace MCP output; shell output is captured + scrubbed, not hidden
        "cursor" => None,
        _ => Some(json!({"decision": "block", "reason": format!("[hivelock masked secrets]\n{text}")})),
    }
}

fn on_start(call: &Call) -> Option<Value> {
    let store = Store::open().ok()?;
    if !call.transcript().is_empty() {
        let _ = Redactor::new(store.mask_pairs()).scrub_file(Path::new(call.transcript()));
    }
    let names = store.visible_names(&call.cwd);
    if names.is_empty() {
        return None;
    }
    let h = hint(call.agent, &names);
    Some(match call.agent {
        "copilot" => json!({"additionalContext": h}),
        "cursor" => json!({"additional_context": h}),
        _ => json!({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": h}}),
    })
}
