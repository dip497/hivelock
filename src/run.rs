use crate::approve;
use crate::audit;
use crate::redact::Redactor;
use crate::vault::Store;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

pub fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{lock:([A-Za-z0-9_]+)\}\}").unwrap())
}

pub fn placeholder_names(s: &str) -> Vec<String> {
    let mut v: Vec<String> = placeholder_re().captures_iter(s).map(|c| c[1].to_string()).collect();
    v.sort();
    v.dedup();
    v
}

#[derive(Clone, Copy, PartialEq)]
pub enum Shell {
    Posix,
    PowerShell,
}

/// Rewrites `{{lock:X}}` into an env reference that is correct for the quote context it sits in.
/// Values never enter the command line (so not visible in `ps`).
pub fn shellify(cmd: &str, shell: Shell) -> String {
    if shell == Shell::PowerShell {
        // ponytail: PowerShell single-quoted strings don't expand; placeholders there stay broken
        return placeholder_re().replace_all(cmd, "$$env:__HL_$1").into_owned();
    }
    let (mut out, mut i) = (String::with_capacity(cmd.len()), 0);
    let (mut single, mut double) = (false, false);
    let b = cmd.as_bytes();
    while i < b.len() {
        if let Some(m) = placeholder_re().captures_at(cmd, i).filter(|c| c.get(0).unwrap().start() == i) {
            let v = format!("${{__HL_{}}}", &m[1]);
            out.push_str(&match (single, double) {
                (true, _) => format!("'\"{v}\"'"),
                (_, true) => v,
                _ => format!("\"{v}\""),
            });
            i = m.get(0).unwrap().end();
            continue;
        }
        let c = b[i];
        match c {
            b'\\' if !single && i + 1 < b.len() => {
                out.push_str(&cmd[i..i + 2]);
                i += 2;
                continue;
            }
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            _ => {}
        }
        let ch_len = cmd[i..].chars().next().map_or(1, |c| c.len_utf8());
        out.push_str(&cmd[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn which(prog: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| d.join(prog).is_file() || d.join(format!("{prog}.exe")).is_file())
    })
}

pub fn in_agent() -> &'static str {
    if std::env::var_os("CLAUDECODE").is_some() {
        "claude"
    } else if std::env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with("CODEX_")) {
        "codex"
    } else {
        ""
    }
}

/// Resolves names → values. Locked ones need the passphrase typed on a real terminal.
fn resolve(store: &Store, names: &[String], cwd: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut locked_map = None;
    for n in names {
        let Some(e) = store.resolve(n, cwd) else {
            return Err(format!("unknown secret {n}. Available: {}", store.visible_names(cwd).join(", ")));
        };
        if e.locked {
            if locked_map.is_none() {
                let pass = rpassword::prompt_password(format!("hivelock: passphrase for locked secret {n}: "))
                    .map_err(|_| format!("{n} is locked: human only. Run this in your own terminal."))?;
                locked_map = Some(store.read_locked(&pass)?);
            }
            let v = locked_map.as_ref().unwrap().get(&format!("{}\n{}", e.scope, e.name));
            out.insert(n.clone(), v.cloned().ok_or(format!("{n}: locked value missing"))?);
        } else {
            out.insert(n.clone(), e.value.clone());
        }
    }
    Ok(out)
}

/// hivelock run [--agent A] [--env A,B] (--b64 X | '<shell cmd>' | -- prog args...)
pub fn run(args: &[String]) -> Result<i32, String> {
    let mut agent = in_agent().to_string();
    let mut grant = String::new();
    let mut ask_form = false;
    let mut env_names: Vec<String> = Vec::new();
    let mut shell_cmd: Option<String> = None;
    let mut argv: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--agent" => {
                agent = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            "--grant" => {
                grant = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            "--ask" => ask_form = true,
            "--env" => {
                env_names.extend(args.get(i + 1).into_iter().flat_map(|s| s.split(',')).map(str::to_string));
                i += 1;
            }
            "--b64" => {
                use base64::Engine;
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(args.get(i + 1).ok_or("--b64 needs a value")?)
                    .map_err(|e| e.to_string())?;
                shell_cmd = Some(String::from_utf8(raw).map_err(|e| e.to_string())?);
                i += 1;
            }
            "--" => {
                argv = args[i + 1..].to_vec();
                break;
            }
            s if shell_cmd.is_none() && argv.is_empty() => shell_cmd = Some(s.to_string()),
            s => return Err(format!("unexpected argument {s}")),
        }
        i += 1;
    }
    if shell_cmd.is_none() && argv.is_empty() {
        return Err("usage: hivelock run '<shell command>'  |  hivelock run [--env A,B] -- prog args...".into());
    }

    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let store = Store::open()?;
    let mut names = env_names.clone();
    names.extend(placeholder_names(shell_cmd.as_deref().unwrap_or("")));
    for a in &argv {
        names.extend(placeholder_names(a));
    }
    names.sort();
    names.dedup();
    // `ask` secrets need the grant issued alongside the agent's native approval prompt,
    // unless a person at a real terminal is running this themselves
    let ask: Vec<&String> = names.iter().filter(|n| store.resolve(n, &cwd).is_some_and(|e| e.ask)).collect();
    if !ask.is_empty() {
        let self_run = agent.is_empty() && approve::human_terminal();
        let key = if ask_form { shell_cmd.as_deref().map(approve::command_key).unwrap_or_default() } else { grant };
        if !self_run && !approve::consume(&key) {
            let list: Vec<&str> = ask.iter().map(|s| s.as_str()).collect();
            audit::log("denied", &agent, &list.join(","), "", 0);
            return Err(format!("{} requires the user's approval in the agent's permission prompt; not approved for this call", list.join(", ")));
        }
        audit::log("approved", &agent, &ask.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","), "", 0);
    }
    let mut values = resolve(&store, &names, &cwd)?;
    // file secrets: the command gets a path to a private temp copy, removed when it exits
    let mut temp_files = Vec::new();
    let mut file_values = Vec::new();
    for (n, v) in values.iter_mut() {
        let Some(e) = store.resolve(n, &cwd).filter(|e| e.file) else { continue };
        let body = if e.kind == "file-b64" {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(v.as_bytes()).map_err(|e| e.to_string())?
        } else {
            let mut b = v.clone().into_bytes();
            if !b.ends_with(b"\n") {
                b.push(b'\n'); // ssh refuses keys without a trailing newline
            }
            b
        };
        let path = std::env::temp_dir().join(format!("hivelock-{}-{}-{}", n.to_ascii_lowercase(), std::process::id(), crate::vault::now()));
        let mut f = crate::vault::private_open(&path, false).map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut f, &body).map_err(|e| e.to_string())?;
        file_values.push((n.clone(), std::mem::replace(v, path.display().to_string())));
        temp_files.push(path);
    }

    let mut cmd = if let Some(sc) = &shell_cmd {
        let (prog, flag, shell) = if which("bash") {
            ("bash", "-c", Shell::Posix)
        } else if cfg!(windows) {
            ("powershell", "-Command", Shell::PowerShell)
        } else {
            ("sh", "-c", Shell::Posix)
        };
        let mut c = Command::new(prog);
        c.arg(flag).arg(shellify(sc, shell));
        c
    } else {
        // no shell: substitute directly into argv
        // ponytail: argv values are visible to same-user `ps`; prefer the shell form or --env
        let sub = |s: &str| placeholder_re().replace_all(s, |c: &regex::Captures| values[&c[1]].clone()).into_owned();
        let mut c = Command::new(sub(&argv[0]));
        c.args(argv[1..].iter().map(|a| sub(a)));
        c
    };
    for (n, v) in &values {
        cmd.env(format!("__HL_{n}"), v);
    }
    for n in &env_names {
        cmd.env(n, &values[n]);
    }

    let prog = shell_cmd
        .as_deref()
        .and_then(|s| s.split_whitespace().next())
        .or(argv.first().map(String::as_str))
        .unwrap_or("")
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_string();
    for n in &names {
        audit::log("injected", &agent, n, &prog, 0);
    }

    let mut pairs = store.mask_pairs();
    pairs.extend(values.iter().filter(|(n, _)| !file_values.iter().any(|(f, _)| f == *n)).map(|(n, v)| (n.clone(), v.clone())));
    pairs.extend(file_values);
    let red = std::sync::Arc::new(Redactor::new(pairs));
    let mut child = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start {prog}: {e}"))?;
    let (out, err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let r2 = red.clone();
    let t = std::thread::spawn(move || r2.copy(err, std::io::stderr()));
    let _ = red.copy(out, std::io::stdout());
    let _ = t.join();
    let status = child.wait().map_err(|e| e.to_string());
    // ponytail: a killed `run` (SIGKILL) leaves its 0600 temp key file behind in the temp dir
    for p in &temp_files {
        let _ = std::fs::remove_file(p);
    }
    let status = status?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(128 + sig);
        }
    }
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shellify_quote_contexts() {
        assert_eq!(shellify("echo {{lock:A}}", Shell::Posix), "echo \"${__HL_A}\"");
        assert_eq!(shellify("curl -H \"Bearer {{lock:A}}\"", Shell::Posix), "curl -H \"Bearer ${__HL_A}\"");
        assert_eq!(shellify("echo 'x {{lock:A}} y'", Shell::Posix), "echo 'x '\"${__HL_A}\"' y'");
        assert_eq!(shellify("echo \\'{{lock:A}}", Shell::Posix), "echo \\'\"${__HL_A}\"");
        assert_eq!(shellify("echo {{lock:A}}", Shell::PowerShell), "echo $env:__HL_A");
    }

    #[test]
    fn shellify_runs_in_bash() {
        let cmd = shellify("printf '%s|' '{{lock:A}}' \"{{lock:A}}\" {{lock:A}}", Shell::Posix);
        let out = Command::new("bash").arg("-c").arg(cmd).env("__HL_A", "va l'\"ue").output().unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "va l'\"ue|va l'\"ue|va l'\"ue|");
    }
}
