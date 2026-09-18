# hivelock

Rust CLI that keeps secrets out of AI coding agents: agents see `{{lock:NAME}}`, never values. Single binary, no daemon, hooks run per agent event (~2 ms budget).

## Commands

```sh
cargo build --release                  # binary: target/release/hivelock
cargo test --release                   # unit tests (must stay green)
cargo clippy --release                 # keep at 0 warnings
cargo check --release --target x86_64-pc-windows-msvc   # also aarch64-apple-darwin; CI runs all 3 OSes
./target/release/hivelock doctor       # self-test incl. latency
./target/release/hivelock scan src .github   # must report only obvious test fixtures before pushing
```

Manual testing: always set `HIVELOCK_HOME=<scratch dir>` and `HIVELOCK_NO_CLIPBOARD=1`, and point agent config at scratch dirs (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`, `HOME`). Never touch the real vault or real agent configs.

## Layout (src/)

- `main.rs` CLI dispatch + help text
- `vault.rs` encrypted store (XChaCha20-Poly1305, key file, scrypt for `locked`), scopes, naming/dedupe
- `detect.rs` gitleaks rules (built into a static table by `build.rs` from `rules/gitleaks.toml`) + generic chat rules + labels + `.env` parsing
- `redact.rs` masking (encoded variants, streaming, same-length in-place scrub)
- `hook.rs` one normalized core for all agents (claude codex gemini qwen copilot cursor); only JSON dialects differ
- `run.rs` placeholder injection, shell quoting, file secrets as temp paths
- `approve.rs` one-time grants for `ask` secrets (native agent prompts only, no dialogs)
- `install.rs` install/uninstall/doctor per agent; `scrub.rs` agent session dirs; `audit.rs` stats; `tui.rs` manager + `setup` onboarding

## Rules that aren't obvious

- Minimal code, no new dependencies without a strong reason. Deliberate shortcuts get a `// ponytail:` comment naming the ceiling.
- Hook output shapes are verified against real agents; don't "clean them up" from docs alone:
  - Claude `updatedToolOutput` must keep the tool's object shape (a plain string is ignored).
  - Codex can't rewrite commands safely, so its hook denies with instructions; Codex `ask` relies on the prompt rule in `~/.codex/rules/hivelock.rules`, plus a check that the session's turn_context isn't full-access / never / auto-review.
  - Claude install sets `CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1`, because title generation leaks blocked prompts; block output also sets `hookSpecificOutput.suppressOriginalPrompt` (it is ignored at top level).
  - Parallel `PreToolUse` hooks that both return `updatedInput`: the one that finishes last wins (verified). With rtk installed, hivelock folds in `rtk rewrite` and replies after 400 ms.
  - No agent lets a hook rewrite the user prompt except Copilot (`userPromptTransformed`) and Gemini (`BeforeModel`). Rewriting the session file doesn't work either (verified: the model still gets the in-memory text). After a block, `hivelock refill` puts the masked text back via tmux/WezTerm/kitty/zellij.
- Rule regexes compile as ASCII byte regexes (Go RE2 semantics). Unicode `\w` made scans ~50x slower.
- Generic detection (`detect_chat`) runs on chat text only, never on auto-captured tool output.
- Tests that set `HIVELOCK_HOME` must hold `vault::TEST_ENV`.
- Test fixtures that look like real secrets are assembled at runtime (`"ghp" + "_..."`) so secret scanners and GitHub push protection don't flag the repo. Never put values from real sessions in tests or docs.
- README stays bare minimum; details go in `docs/` (usage, agents, security), also short.
- `PLAN.md` is local-only (gitignored).

## Release

Run `scripts/release.sh` on a clean, synced `main`. It sets the calendar version `YYYY.M.N` (the Nth release of that month, from 0) in `Cargo.toml`, refreshes `Cargo.lock`, commits and pushes, waits for CI, then pushes the `vYYYY.M.N` tag. `--dry-run` prints the version and stops. Releases up to v0.0.3 used semver. `release.yml` builds 5 targets, publishes with SHA256SUMS, then `install.yml` verifies `install.sh` / `install.ps1` on Linux, macOS and Windows (PowerShell, cmd, Git Bash). Commits use the repo-local noreply identity (`dip497`).
