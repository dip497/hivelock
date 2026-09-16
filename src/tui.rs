//! Small full-screen manager. Reads the vault for the list; every action shells out to the
//! regular `hivelock` subcommands so behavior (and prompts) stay identical to the CLI.
use crate::vault::{now, Entry, Store};
use crossterm::cursor::{Hide, MoveTo, MoveToColumn, MoveUp, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::style::{Attribute, Print, SetAttribute};
use crossterm::terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, queue};
use std::io::{self, Write};
use std::process::{Command, Stdio};

const KEYS: &str = "↑↓ move  a add  i import  r rename  d retire  l lock/unlock  k ask/open  s stats  q quit";

fn entries() -> Vec<Entry> {
    Store::open().map(|s| s.live().cloned().collect()).unwrap_or_default()
}

fn ago(ts: u64) -> String {
    let d = now().saturating_sub(ts) / 86400;
    if d == 0 { "today".into() } else { format!("{d}d") }
}

/// Pad or cut at the end (names, lines): the start is what tells entries apart.
fn fit_end(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        format!("{s:<w$}")
    } else {
        let head: String = s.chars().take(w.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn short_scope(scope: &str) -> String {
    let home = crate::vault::home().display().to_string();
    match scope.strip_prefix(&home) {
        Some(rest) if !home.is_empty() => format!("~{rest}"),
        _ => scope.to_string(),
    }
}

/// Pad or cut at the start (paths): the end is the meaningful part.
fn fit(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w {
        format!("{s:<w$}")
    } else {
        let tail: String = s.chars().skip(n - (w - 1)).collect();
        format!("…{tail}")
    }
}

/// Runs `hivelock args...` from the entry's project dir (so scoped names resolve); returns last output line.
fn cli(args: &[&str], dir: Option<&str>, stdin: Option<&str>) -> String {
    let Ok(exe) = std::env::current_exe() else { return "cannot find hivelock binary".into() };
    let mut c = Command::new(exe);
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(d) = dir.filter(|d| *d != "global" && std::path::Path::new(d).is_dir()) {
        c.current_dir(d);
    }
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::inherit() });
    let Ok(mut child) = c.spawn() else { return "failed to run hivelock".into() };
    if let (Some(v), Some(mut i)) = (stdin, child.stdin.take()) {
        let _ = i.write_all(v.as_bytes());
    }
    let out = child.wait_with_output().map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)));
    out.unwrap_or_default().lines().rfind(|l| !l.trim().is_empty()).unwrap_or("done").to_string()
}

/// Leaves raw mode for a line of cooked input on the bottom row (hidden when `secret`).
fn ask_line(label: &str, secret: bool) -> io::Result<String> {
    let (_, rows) = terminal::size()?;
    terminal::disable_raw_mode()?;
    execute!(io::stdout(), MoveTo(0, rows - 1), Clear(ClearType::CurrentLine), Show)?;
    let v = if secret {
        rpassword::prompt_password(label)?
    } else {
        print!("{label}");
        io::stdout().flush()?;
        let mut s = String::new();
        io::stdin().read_line(&mut s)?;
        s.trim().to_string()
    };
    execute!(io::stdout(), Hide)?;
    terminal::enable_raw_mode()?;
    Ok(v)
}

fn draw(list: &[Entry], sel: usize, status: &str, stats: Option<&str>) -> io::Result<()> {
    let (cols, rows) = terminal::size()?;
    let (w, h) = (cols as usize, rows as usize);
    let mut out = io::stdout();
    queue!(out, Clear(ClearType::All), MoveTo(0, 0))?;
    let locked = list.iter().filter(|e| e.locked).count();
    let ask = list.iter().filter(|e| e.ask).count();
    queue!(
        out,
        SetAttribute(Attribute::Bold),
        Print(fit_end(&format!(" hivelock   {} secrets · {locked} locked · {ask} ask", list.len()), w)),
        SetAttribute(Attribute::Reset)
    )?;
    if let Some(text) = stats {
        for (i, line) in text.lines().take(h.saturating_sub(3)).enumerate() {
            queue!(out, MoveTo(0, i as u16 + 2), Print(fit_end(line, w)))?;
        }
        queue!(out, MoveTo(0, rows - 2), Print(fit_end(" any key: back", w)))?;
        return out.flush();
    }
    let kinds: Vec<String> = list.iter().map(|e| if e.file { format!("{} ·file", e.kind) } else { e.kind.clone() }).collect();
    let longest = |it: &mut dyn Iterator<Item = usize>, min: usize| it.max().unwrap_or(0).max(min);
    let kind_w = longest(&mut kinds.iter().map(|k| k.chars().count()), 4).min(22);
    let name_w = longest(&mut list.iter().map(|e| e.name.chars().count()), 4).min((w / 2).max(12));
    let scope_w = longest(&mut list.iter().map(|e| short_scope(&e.scope).chars().count()), 5).min(w.saturating_sub(name_w + kind_w + 7 + 6 + 6).max(8));
    let row = |name: &str, level: &str, kind: &str, scope: &str, added: &str| {
        fit_end(&format!(" {} {level:<7} {} {} {added:>6}", fit_end(name, name_w), fit_end(kind, kind_w), fit(scope, scope_w)), w)
    };
    queue!(out, MoveTo(0, 2), SetAttribute(Attribute::Dim), Print(row("NAME", "LEVEL", "KIND", "SCOPE", "ADDED")), SetAttribute(Attribute::Reset))?;
    let body = h.saturating_sub(6);
    let first = sel.saturating_sub(body.saturating_sub(1));
    for (r, (i, e)) in list.iter().enumerate().skip(first).take(body).enumerate() {
        let level = if e.locked { "locked" } else if e.ask { "ask" } else { "open" };
        let line = row(&e.name, level, &kinds[i], &short_scope(&e.scope), &ago(e.created));
        queue!(out, MoveTo(0, r as u16 + 3))?;
        if i == sel {
            queue!(out, SetAttribute(Attribute::Reverse), Print(line), SetAttribute(Attribute::Reset))?;
        } else {
            queue!(out, Print(line))?;
        }
    }
    if list.is_empty() {
        queue!(out, MoveTo(1, 4), Print("no secrets yet: press a to add, i to import a .env or key file"))?;
    }
    queue!(out, MoveTo(0, rows - 3), SetAttribute(Attribute::Dim), Print(fit_end(KEYS, w)), SetAttribute(Attribute::Reset))?;
    queue!(out, MoveTo(0, rows - 2), Print(fit_end(&format!(" {status}"), w)))?;
    out.flush()
}

pub fn run() -> io::Result<()> {
    use std::io::IsTerminal;
    if !io::stdout().is_terminal() {
        print!("{}", crate::HELP);
        return Ok(());
    }
    if !Store::initialized() {
        println!("{}", cli(&["init"], None, None));
    }
    terminal::enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, Hide)?;
    let result = main_loop();
    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
    result
}

fn main_loop() -> io::Result<()> {
    let mut list = entries();
    let mut sel = 0usize;
    let mut status = String::from("values are never shown here");
    let mut stats: Option<String> = None;
    loop {
        sel = sel.min(list.len().saturating_sub(1));
        draw(&list, sel, &status, stats.as_deref())?;
        let Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. }) = event::read()? else { continue };
        if stats.take().is_some() {
            continue;
        }
        let cur = list.get(sel).cloned();
        let scope = cur.as_ref().map(|e| e.scope.clone());
        let name = cur.as_ref().map(|e| e.name.clone()).unwrap_or_default();
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Up => sel = sel.saturating_sub(1),
            KeyCode::Down => sel += 1,
            KeyCode::Char('a') => {
                let n = ask_line("name (UPPER_SNAKE): ", false)?;
                if !n.is_empty() {
                    let v = ask_line(&format!("value for {n} (hidden): "), true)?;
                    status = if v.is_empty() { "cancelled".into() } else { cli(&["add", &n], None, Some(&v)) };
                }
            }
            KeyCode::Char('i') => {
                let p = ask_line("import file (.env, .pem, id_rsa, .p12, json key): ", false)?;
                if !p.is_empty() {
                    status = cli(&["import", &p], None, None);
                }
            }
            KeyCode::Char('r') if cur.is_some() => {
                let n = ask_line(&format!("rename {name} to: "), false)?;
                if !n.is_empty() {
                    status = cli(&["mv", &name, &n], scope.as_deref(), None);
                }
            }
            KeyCode::Char('d') if cur.is_some() => {
                if ask_line(&format!("retire {name}? values stay masked (y/N): "), false)?.eq_ignore_ascii_case("y") {
                    status = cli(&["rm", &name], scope.as_deref(), None);
                }
            }
            KeyCode::Char('l') if cur.is_some() => {
                let sub = if cur.as_ref().is_some_and(|e| e.locked) { "unlock" } else { "lock" };
                terminal::disable_raw_mode()?;
                let (_, rows) = terminal::size()?;
                execute!(io::stdout(), MoveTo(0, rows - 1), Clear(ClearType::CurrentLine), Show)?;
                status = cli(&[sub, &name], scope.as_deref(), None); // passphrase prompt goes to the tty
                execute!(io::stdout(), Hide)?;
                terminal::enable_raw_mode()?;
            }
            KeyCode::Char('k') if cur.is_some() => {
                let sub = if cur.as_ref().is_some_and(|e| e.ask) { "open" } else { "ask" };
                status = cli(&[sub, &name], scope.as_deref(), None);
            }
            KeyCode::Char('s') => {
                let exe = std::env::current_exe()?;
                let o = Command::new(exe).arg("stats").output()?;
                stats = Some(String::from_utf8_lossy(&o.stdout).into_owned());
            }
            _ => {}
        }
        list = entries();
    }
}

const AGENT_LABELS: &[(&str, &str, &[&str])] = &[
    ("claude", "Claude Code", &["claude"]),
    ("codex", "Codex", &["codex"]),
    ("copilot", "GitHub Copilot CLI", &["copilot"]),
    ("gemini", "Gemini CLI", &["gemini"]),
    ("cursor", "Cursor", &["cursor-agent", "cursor"]),
    ("qwen", "Qwen Code", &["qwen"]),
];

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| ["", ".exe", ".cmd"].iter().any(|ext| d.join(format!("{bin}{ext}")).is_file()))
    })
}

fn found(agent: &str, bins: &[&str]) -> bool {
    bins.iter().any(|b| on_path(b)) || crate::scrub::agent_dir(agent).is_dir()
}

/// Interactive multi-select (all ticked by default). None = cancelled.
fn pick_agents(found: &[bool]) -> io::Result<Option<Vec<bool>>> {
    let mut on = vec![true; AGENT_LABELS.len()];
    let mut cur = 0;
    let rows = AGENT_LABELS.len() as u16 + 2;
    let mut out = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(out, Hide)?;
    let draw = |out: &mut io::Stdout, on: &[bool], cur: usize, first: bool| -> io::Result<()> {
        if !first {
            queue!(out, MoveUp(rows), MoveToColumn(0))?;
        }
        queue!(out, Clear(ClearType::FromCursorDown), Print("Which agents should hivelock protect?\r\n"))?;
        for (i, (_, label, _)) in AGENT_LABELS.iter().enumerate() {
            let mark = if on[i] { "[x]" } else { "[ ]" };
            let state = if found[i] { "found" } else { "not found" };
            let line = format!("{} {mark} {label:<20} {state}\r\n", if i == cur { ">" } else { " " });
            if i == cur {
                queue!(out, SetAttribute(Attribute::Bold), Print(line), SetAttribute(Attribute::Reset))?;
            } else {
                queue!(out, Print(line))?;
            }
        }
        queue!(out, SetAttribute(Attribute::Dim), Print("↑↓ move · space toggle · a all · enter install · esc skip"), SetAttribute(Attribute::Reset))?;
        out.flush()
    };
    draw(&mut out, &on, cur, true)?;
    let result = loop {
        let Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. }) = event::read()? else { continue };
        match code {
            KeyCode::Up | KeyCode::Char('k') => cur = cur.checked_sub(1).unwrap_or(on.len() - 1),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => cur = (cur + 1) % on.len(),
            KeyCode::Char(' ') => on[cur] = !on[cur],
            KeyCode::Char('a') => {
                let all = on.iter().all(|x| *x);
                on.iter_mut().for_each(|x| *x = !all);
            }
            KeyCode::Enter => break Some(on.clone()),
            KeyCode::Esc | KeyCode::Char('q') => break None,
            _ => {}
        }
        draw(&mut out, &on, cur, false)?;
    };
    terminal::disable_raw_mode()?;
    execute!(out, Show, Print("\r\n"))?;
    Ok(result)
}

/// `hivelock setup [--all | --agents a,b]`: first-run onboarding.
pub fn setup(args: &[String]) -> Result<i32, String> {
    use std::io::IsTerminal;
    let found: Vec<bool> = AGENT_LABELS.iter().map(|(a, _, bins)| found(a, bins)).collect();
    let flag = |f: &str| args.iter().position(|a| a == f);
    let chosen: Vec<bool> = if let Some(i) = flag("--agents") {
        let list = args.get(i + 1).ok_or("--agents needs a list, e.g. claude,codex")?;
        AGENT_LABELS.iter().map(|(a, _, _)| list.split(',').any(|x| x.trim() == *a)).collect()
    } else if flag("--all").is_some() {
        vec![true; AGENT_LABELS.len()]
    } else if io::stdin().is_terminal() && io::stdout().is_terminal() {
        match pick_agents(&found).map_err(|e| e.to_string())? {
            Some(c) => c,
            None => {
                println!("skipped. run `hivelock setup` any time.");
                return Ok(0);
            }
        }
    } else {
        println!("run `hivelock setup` in a terminal, or `hivelock setup --all` / `--agents claude,codex`");
        return Ok(0);
    };

    if Store::init()? {
        println!("created your vault in {}", crate::vault::data_dir().display());
    }
    let mut failed = 0;
    for ((agent, label, _), _) in AGENT_LABELS.iter().zip(&chosen).filter(|(_, c)| **c) {
        match crate::install::install(agent) {
            Ok(()) => {}
            Err(e) => {
                failed += 1;
                println!("  {label}: {e}");
            }
        }
    }
    if chosen.iter().any(|c| *c) {
        println!("\ndone. restart your agents, then just work: paste a secret and hivelock holds it back.");
        println!("move existing secrets in with `hivelock import .env`; `hivelock doctor` checks everything.");
    } else {
        println!("no agents selected. run `hivelock setup` any time.");
    }
    Ok(if failed > 0 { 1 } else { 0 })
}
