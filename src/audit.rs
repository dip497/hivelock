use crate::vault::{data_dir, now, private_open, Store};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;

/// Append one event. Never pass secret values here: names and program names only.
pub fn log(ev: &str, agent: &str, name: &str, prog: &str, ms: u128) {
    let line = json!({"ts": now(), "ev": ev, "agent": agent, "name": name, "prog": prog, "ms": ms as u64});
    if let Ok(mut f) = private_open(&data_dir().join("audit.jsonl"), true) {
        let _ = writeln!(f, "{line}");
    }
}

fn ago(ts: u64) -> String {
    let d = now().saturating_sub(ts);
    match d {
        0..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
}

pub fn stats(prune_days: Option<u64>) -> Result<(), String> {
    let path = data_dir().join("audit.jsonl");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let events: Vec<Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();

    if let Some(days) = prune_days {
        let cutoff = now().saturating_sub(days * 86400);
        let kept: Vec<String> = events
            .iter()
            .filter(|e| e["ts"].as_u64().unwrap_or(0) >= cutoff)
            .map(|e| e.to_string())
            .collect();
        let mut f = private_open(&path, false).map_err(|e| e.to_string())?;
        for l in &kept {
            writeln!(f, "{l}").map_err(|e| e.to_string())?;
        }
        println!("pruned {} events older than {days}d", events.len() - kept.len());
        return Ok(());
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    // name -> (uses, last ts, agents)
    let mut per: BTreeMap<String, (usize, u64, Vec<String>)> = BTreeMap::new();
    let mut ms: Vec<u64> = Vec::new();
    for e in &events {
        let ev = e["ev"].as_str().unwrap_or("?");
        *counts.entry(ev).or_default() += 1;
        if let Some(m) = e["ms"].as_u64().filter(|m| *m > 0) {
            ms.push(m);
        }
        if ev == "injected" {
            let p = per.entry(e["name"].as_str().unwrap_or("").to_string()).or_default();
            p.0 += 1;
            p.1 = p.1.max(e["ts"].as_u64().unwrap_or(0));
            let a = e["agent"].as_str().unwrap_or("").to_string();
            if !a.is_empty() && !p.2.contains(&a) {
                p.2.push(a);
            }
        }
    }

    let store = Store::open().ok();
    let live: Vec<_> = store.as_ref().map(|s| s.live().cloned().collect()).unwrap_or_default();
    let locked = live.iter().filter(|e| e.locked).count();
    let c = |k: &str| counts.get(k).copied().unwrap_or(0);
    println!(
        "secrets {} ({} locked)   pastes blocked {}   auto-captured {}   redactions {}   denied {}",
        live.len(),
        locked,
        c("blocked_prompt"),
        c("captured"),
        c("redacted"),
        c("denied")
    );
    println!("injected {}   scrubbed {}   imported {}", c("injected"), c("scrubbed"), c("imported"));
    println!();
    for e in &live {
        match per.get(&e.name) {
            Some((n, last, agents)) => {
                println!("  {:<28} used {:<4} last {:<9} {}", e.name, n, ago(*last), agents.join(", "))
            }
            None if now().saturating_sub(e.created) > 90 * 86400 => {
                println!("  {:<28} never used in 90d+  → rotate or `hivelock rm {}`?", e.name, e.name)
            }
            None => println!("  {:<28} used 0", e.name),
        }
    }
    if !ms.is_empty() {
        ms.sort_unstable();
        let pct = |p: usize| ms[(ms.len() - 1) * p / 100];
        println!("\nhook latency (events)  p50 {}ms  p99 {}ms", pct(50), pct(99));
    }
    Ok(())
}
