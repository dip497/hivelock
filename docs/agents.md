# Agents

`hivelock setup` (or `hivelock install <agent>`) adds hooks to the agent's user config and backs up the file first. `hivelock uninstall <agent>` removes only what was added.

| Agent | Pasted secret | Placeholders in commands | Output masked | `ask` |
|---|---|---|---|---|
| Claude Code | held back | rewritten automatically | yes | native prompt |
| Codex | held back | agent wraps with `hivelock run` | yes | Codex approval rule |
| Copilot CLI ≥ 1.0.85 | masked in place | rewritten automatically | yes | native prompt |
| Gemini CLI | held back | rewritten automatically | yes | refused |
| Cursor | held back | agent wraps with `hivelock run` | no | native prompt |
| Qwen Code | held back | agent wraps with `hivelock run` | yes | native prompt |

Tested end to end so far: Claude Code, Codex, and Copilot prompt masking. The rest follow each agent's hook docs, so please report problems.

## Notes

- **When a message is held back:** the masked version is put back into the agent's input box, so you just press Enter. This works in tmux, WezTerm, kitty and zellij; in other terminals the masked version is copied to your clipboard instead.
- **rtk:** if rtk's hook is installed too, hivelock folds rtk's rewrite into its own, so both work on the same command.
- **Claude Code:** the held-back message isn't echoed back on screen. Install sets `CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1`. Without it, Claude Code sends your first message to a model to write a session title, even when a hook holds that message back.
- **Codex:**
  - Trust the hooks once with `/hooks`.
  - `ask` secrets use a prompt rule in `~/.codex/rules/hivelock.rules`, and are refused in sessions without approval prompts (full access, `never`, or automatic review).
- **Copilot:** older versions don't run the hook that masks prompts.
- **Gemini:** secrets in anything sent to the model (files, tool results, earlier turns) are masked in the outgoing request.
- **Cursor:** it can't replace shell output, so secrets that show up in output are captured and scrubbed from disk, but the model has already seen them.
