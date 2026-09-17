mod approve;
mod audit;
mod detect;
mod hook;
mod install;
mod redact;
mod run;
mod scrub;
mod tui;
mod vault;

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use vault::{now, valid_name, Store};

pub const HELP: &str = "hivelock — local secret locker for AI coding agents

agents see names ({{lock:NAME}}), never values. run `hivelock` alone for the manager UI.

setup
  setup [--all|--agents a,b]   pick agents to protect (runs after install)
  init                         create vault + key
  install <agent>              add hooks: claude codex gemini qwen copilot cursor
  uninstall <agent>            remove hooks
  doctor                       verify hooks, vault, self-test, latency

secrets
  add NAME [--project]         store a secret (value from hidden prompt or stdin)
  import FILE [--name N] [--global] [--all] [--rewrite]
                               auto-detects: .env → its secret variables;
                               keys (.pem, id_rsa, .p12, service-account json, kubeconfig) → file secret
  ls [--all]                   list names (never values)
  rm NAME                      retire a secret (still masked in output)
  mv OLD NEW                   rename (replaces NEW if it exists)
  lock NAME / unlock NAME      human-only: passphrase-encrypted, agents cannot use it
  ask NAME                     agents need your approval in their own permission prompt, every use
  open NAME                    agents may use it without asking
  purge --yes                  forget retired values

use
  run '<shell command>'        inject {{lock:NAME}} and mask output
  run [--env A,B] -- prog args
  scan PATH... [--rules-only]  report secrets in files (nothing stored, values hidden)
  scrub [--agent NAME]         mask known secrets in saved agent sessions
  stats [--prune DAYS]         usage + audit summary
";

fn main() {
    // `hivelock ls | head` should exit quietly, not panic on a closed pipe
    #[cfg(unix)]
    {
        extern "C" {
            fn signal(sig: i32, handler: usize) -> usize;
        }
        unsafe { signal(13, 0) }; // SIGPIPE → SIG_DFL
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match dispatch(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hivelock: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn flag(args: &[String], f: &str) -> bool {
    args.iter().any(|a| a == f)
}

fn opt<'a>(args: &'a [String], f: &str) -> Option<&'a str> {
    args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn positional(args: &[String], i: usize) -> Result<&str, String> {
    args.iter()
        .filter(|a| !a.starts_with("--"))
        .nth(i)
        .map(String::as_str)
        .ok_or_else(|| "missing argument, see `hivelock help`".to_string())
}

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_default()
}

fn scope(project: bool) -> String {
    if project { cwd().to_string_lossy().into_owned() } else { "global".into() }
}

fn passphrase(store: &Store, why: &str) -> Result<String, String> {
    let p = rpassword::prompt_password(format!("{why} passphrase: ")).map_err(|_| "locking needs a real terminal".to_string())?;
    if !store.has_locked_file() {
        let again = rpassword::prompt_password("repeat passphrase: ").map_err(|e| e.to_string())?;
        if p != again {
            return Err("passphrases differ".into());
        }
        if p.len() < 8 {
            return Err("passphrase must be at least 8 characters".into());
        }
    }
    Ok(p)
}

fn dispatch(args: &[String]) -> Result<i32, String> {
    let Some(cmd) = args.first().map(String::as_str) else {
        use std::io::IsTerminal;
        if !Store::initialized() && std::io::stdout().is_terminal() {
            return tui::setup(&[]); // first run: onboarding
        }
        tui::run().map_err(|e| e.to_string())?;
        return Ok(0);
    };
    let rest = &args[args.len().min(1)..];
    match cmd {
        "hook" => return Ok(hook::hook(positional(rest, 0)?, positional(rest, 1)?)),
        "refill" => return Ok(hook::refill(positional(rest, 0)?, positional(rest, 1)?)),
        "run" => return run::run(rest),
        "doctor" => return install::doctor(),
        "init" => {
            let created = Store::init()?;
            println!("{} {}", if created { "created vault in" } else { "vault already exists in" }, vault::data_dir().display());
        }
        "setup" => return tui::setup(rest),
        "install" => install::install(positional(rest, 0)?)?,
        "uninstall" => install::uninstall(positional(rest, 0)?)?,
        "add" => {
            let name = positional(rest, 0)?;
            if !valid_name(name) {
                return Err(format!("invalid name {name}: use UPPER_SNAKE_CASE"));
            }
            let value = if std::io::stdin().is_terminal() {
                rpassword::prompt_password(format!("value for {name}: ")).map_err(|e| e.to_string())?
            } else {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s).map_err(|e| e.to_string())?;
                s.trim_end_matches(['\n', '\r']).to_string()
            };
            if value.is_empty() {
                return Err("empty value".into());
            }
            Store::init()?;
            let mut s = Store::open_rw()?;
            let (stored, new) = s.add(name, &value, "manual", &scope(flag(rest, "--project")), "cli");
            s.save()?;
            match (new, stored == name) {
                (false, _) => println!("same value already stored as {stored}"),
                (true, true) => println!("stored {stored}"),
                (true, false) => println!("{name} already exists in this scope; stored as {stored} (`hivelock mv {stored} {name}` to replace)"),
            }
            if value.len() < redact::MIN_LEN {
                println!("note: values shorter than {} chars are not masked in output", redact::MIN_LEN);
            }
        }
        "import" => {
            let file = positional(rest, 0)?;
            let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
            let path = std::path::Path::new(file);
            let base = path.file_name().and_then(|n| n.to_str()).unwrap_or(file);
            let text = String::from_utf8(bytes.clone()).ok();
            let is_env = base == ".env" || base.starts_with(".env.") || base.ends_with(".env");
            // key material: PEM/openssh keys, service-account json, kubeconfig, binary keystores
            let kind = match &text {
                None => Some("file-b64"),
                Some(_) if is_env => None,
                Some(t) if t.contains("PRIVATE KEY-----") || t.contains("\"private_key\"") || t.contains("client-key-data") => Some("file"),
                Some(t) if detect::parse_env(t).is_empty() => Some("file"),
                _ => None,
            };
            let abs = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
            let default_scope = if flag(rest, "--global") || !abs.starts_with(cwd()) { "global".to_string() } else { scope(true) };
            Store::init()?;
            let mut s = Store::open_rw()?;
            if let Some(kind) = kind {
                use base64::Engine;
                let value = match &text {
                    Some(t) => t.clone(),
                    None => base64::engine::general_purpose::STANDARD.encode(&bytes),
                };
                let hint = opt(rest, "--name").map(str::to_string).unwrap_or_else(|| vault::sanitize_name(base.trim_start_matches('.')));
                let (name, new) = s.add(&hint, &value, kind, &default_scope, &format!("import:{file}"));
                s.save()?;
                audit::log("imported", "", &name, "", 0);
                println!(
                    "{} {name} as a file secret (scope: {default_scope}). Use {{{{lock:{name}}}}} wherever a file path is expected (e.g. ssh -i, --cert, GOOGLE_APPLICATION_CREDENTIALS).",
                    if new { "stored" } else { "already stored as" }
                );
                println!("you can now delete the original: {file}");
                return Ok(0);
            }
            let text = text.unwrap_or_default();
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            let mut count = 0;
            for (i, k, v) in detect::parse_env(&text) {
                let take = detect::env_secretish(&k, &v) || (flag(rest, "--all") && !v.is_empty() && !v.contains("{{lock:"));
                if !take {
                    continue;
                }
                let (name, _) = s.add(&k, &v, "dotenv", &default_scope, &format!("import:{file}"));
                lines[i] = format!("{k}={{{{lock:{name}}}}}");
                println!("  {k} → {name}");
                audit::log("imported", "", &name, "", 0);
                count += 1;
            }
            s.save()?;
            if flag(rest, "--rewrite") && count > 0 {
                std::fs::write(file, lines.join("\n") + "\n").map_err(|e| e.to_string())?;
                println!("rewrote {file} with placeholders; run your app with `hivelock run --env NAME,... -- <cmd>`");
            }
            println!("imported {count} secrets (scope: {default_scope})");
        }
        "ls" => {
            let s = Store::open()?;
            let all = flag(rest, "--all");
            println!("{:<28} {:<7} {:<24} {:<22} AGE", "NAME", "LEVEL", "KIND", "SCOPE");
            for e in s.vault.entries.iter().filter(|e| all || !e.retired) {
                let level = if e.retired { "retired" } else if e.locked { "locked" } else if e.ask { "ask" } else { "open" };
                let days = now().saturating_sub(e.created) / 86400;
                let mut sc = e.scope.clone();
                if sc.len() > 22 {
                    sc = format!("…{}", &sc[sc.len() - 21..]);
                }
                let kind = if e.file { format!("{} (file)", e.kind) } else { e.kind.clone() };
                println!("{:<28} {:<7} {:<24} {:<22} {days}d", e.name, level, kind, sc);
            }
        }
        "rm" | "lock" | "unlock" | "mv" | "ask" | "open" => {
            let name = positional(rest, 0)?;
            let mut s = Store::open_rw()?;
            let idx = s.resolve_idx(name, &cwd()).ok_or(format!("no secret {name} visible from here"))?;
            let key = format!("{}\n{}", s.vault.entries[idx].scope, name);
            match cmd {
                "ask" | "open" => {
                    s.vault.entries[idx].ask = cmd == "ask";
                    println!(
                        "{name}: {}",
                        if cmd == "ask" { "agents must get your approval on each use" } else { "agents may use it without asking" }
                    );
                }
                "rm" => {
                    s.vault.entries[idx].retired = true;
                    println!("retired {name} (still masked; `hivelock purge --yes` forgets it)");
                }
                "mv" => {
                    let new = positional(rest, 1)?;
                    if !valid_name(new) {
                        return Err(format!("invalid name {new}"));
                    }
                    if s.vault.entries[idx].locked {
                        return Err("unlock it before renaming".into());
                    }
                    let sc = s.vault.entries[idx].scope.clone();
                    for e in s.vault.entries.iter_mut().filter(|e| !e.retired && e.name == new && e.scope == sc) {
                        e.retired = true;
                    }
                    s.vault.entries[idx].name = new.to_string();
                    println!("renamed {name} → {new}");
                }
                "lock" => {
                    if s.vault.entries[idx].locked {
                        return Err(format!("{name} is already locked"));
                    }
                    let pass = passphrase(&s, "lock")?;
                    let mut map: BTreeMap<String, String> = s.read_locked(&pass)?;
                    map.insert(key, std::mem::take(&mut s.vault.entries[idx].value));
                    s.write_locked(&pass, &map)?;
                    s.vault.entries[idx].locked = true;
                    println!("locked {name}: human-only, agents cannot use or see it");
                }
                _ => {
                    if !s.vault.entries[idx].locked {
                        return Err(format!("{name} is not locked"));
                    }
                    let pass = passphrase(&s, "unlock")?;
                    let mut map = s.read_locked(&pass)?;
                    s.vault.entries[idx].value = map.remove(&key).ok_or("locked value missing")?;
                    s.vault.entries[idx].locked = false;
                    s.save()?;
                    s.write_locked(&pass, &map)?;
                    println!("unlocked {name}");
                }
            }
            s.save()?;
        }
        "purge" => {
            if !flag(rest, "--yes") {
                return Err("this permanently forgets retired values (they stop being masked). Re-run with --yes".into());
            }
            let mut s = Store::open_rw()?;
            let before = s.vault.entries.len();
            s.vault.entries.retain(|e| !e.retired);
            s.save()?;
            println!("purged {} retired secrets", before - s.vault.entries.len());
        }
        "scrub" => {
            if let Some(ms) = opt(rest, "--delay").and_then(|d| d.parse().ok()) {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
            let files: Vec<PathBuf> =
                rest.iter().enumerate().filter(|(i, _)| *i > 0 && rest[i - 1] == "--file").map(|(_, f)| f.into()).collect();
            let (paths, agent) = if files.is_empty() {
                let agent = opt(rest, "--agent").unwrap_or("all");
                let agents: &[&str] = if agent == "all" { hook::AGENTS } else { std::slice::from_ref(&agent) };
                (agents.iter().flat_map(|a| scrub::targets(a)).collect(), agent)
            } else {
                (files, "hook")
            };
            let t0 = std::time::Instant::now();
            let (n, hits) = scrub::scrub_paths(&paths, agent)?;
            if agent != "hook" && !flag(rest, "--quiet") {
                println!("scanned {n} files in {:.1}s, masked {hits} occurrences", t0.elapsed().as_secs_f32());
            }
        }
        "scan" => {
            let mut files = Vec::new();
            for p in rest.iter().filter(|a| !a.starts_with("--")) {
                scrub::walk(std::path::Path::new(p), &mut files);
            }
            let mut total = 0;
            for f in files {
                let Ok(bytes) = std::fs::read(&f) else { continue };
                if bytes.len() > 16 << 20 || bytes[..bytes.len().min(8192)].contains(&0) {
                    continue; // big or binary
                }
                let text = String::from_utf8_lossy(&bytes);
                let found = if flag(rest, "--rules-only") { detect::detect(&text) } else { detect::detect_chat(&text) };
                for d in found {
                    let line = text[..d.start].matches('\n').count() + 1;
                    let shown: String = d.value.chars().take(4).collect();
                    println!("{}:{line}\t{}\t{}\t{shown}****", f.display(), d.kind, d.name);
                    total += 1;
                }
            }
            eprintln!("{total} findings");
            return Ok(if total > 0 { 3 } else { 0 });
        }
        "stats" => audit::stats(opt(rest, "--prune").and_then(|d| d.parse().ok()))?,
        "version" | "--version" | "-V" => println!("hivelock {}", env!("CARGO_PKG_VERSION")),
        "help" | "--help" | "-h" => print!("{HELP}"),
        other => return Err(format!("unknown command {other}, see `hivelock help`")),
    }
    Ok(0)
}
