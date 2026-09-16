//! Small full-screen manager. Reads the vault for the list; every action shells out to the
//! regular `hivelock` subcommands so behavior (and prompts) stay identical to the CLI.
use crate::vault::{now, Entry, Store};
use crossterm::cursor::{Hide, MoveTo, Show};
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
        Print(fit(&format!(" hivelock   {} secrets · {locked} locked · {ask} ask", list.len()), w)),
        SetAttribute(Attribute::Reset)
    )?;
    if let Some(text) = stats {
        for (i, line) in text.lines().take(h.saturating_sub(3)).enumerate() {
            queue!(out, MoveTo(0, i as u16 + 2), Print(fit(line, w)))?;
        }
        queue!(out, MoveTo(0, rows - 2), Print(fit(" any key: back", w)))?;
        return out.flush();
    }
    let name_w = 28.min(w / 3);
    let header = format!(" {} {:<7} {:<18} {:<22} {:>6}", fit("NAME", name_w), "LEVEL", "KIND", "SCOPE", "ADDED");
    queue!(out, MoveTo(0, 2), SetAttribute(Attribute::Dim), Print(fit(&header, w)), SetAttribute(Attribute::Reset))?;
    let body = h.saturating_sub(6);
    let first = sel.saturating_sub(body.saturating_sub(1));
    for (row, (i, e)) in list.iter().enumerate().skip(first).take(body).enumerate() {
        let level = if e.locked { "locked" } else if e.ask { "ask" } else { "open" };
        let kind = if e.file { format!("{} ·file", e.kind) } else { e.kind.clone() };
        let line = format!(" {} {:<7} {} {} {:>6}", fit(&e.name, name_w), level, fit(&kind, 18), fit(&e.scope, 22), ago(e.created));
        queue!(out, MoveTo(0, row as u16 + 3))?;
        if i == sel {
            queue!(out, SetAttribute(Attribute::Reverse), Print(fit(&line, w)), SetAttribute(Attribute::Reset))?;
        } else {
            queue!(out, Print(fit(&line, w)))?;
        }
    }
    if list.is_empty() {
        queue!(out, MoveTo(1, 4), Print("no secrets yet: press a to add, i to import a .env or key file"))?;
    }
    queue!(out, MoveTo(0, rows - 3), SetAttribute(Attribute::Dim), Print(fit(KEYS, w)), SetAttribute(Attribute::Reset))?;
    queue!(out, MoveTo(0, rows - 2), Print(fit(&format!(" {status}"), w)))?;
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
