# hivelock

**Keep secrets out of your AI coding agent.** It sees names, never values.

> *I kept handing secrets to my coding agent.* Paste the API key into the prompt, or just say **"read it from my `.env`"**.
>
> It works — and now that key sits with the model provider, in the session log on disk, and in whatever output the agent prints next.

hivelock holds that message back before it's sent. The secret goes into a local encrypted vault, and you resend it by name:

```diff
- STRIPE_SECRET_KEY=sk_live_…the real key you just pasted…
+ STRIPE_SECRET_KEY={{lock:STRIPE_SECRET_KEY}}
```

The agent only ever works with `{{lock:STRIPE_SECRET_KEY}}`. When it runs a command, hivelock fills in the real value at the last moment and masks it again in the output:

```console
$ curl -H "Authorization: Bearer {{lock:GITHUB_TOKEN}}" api.github.com/user
[lock:GITHUB_TOKEN]   ← what the agent gets back
```

---

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/dip497/hivelock/main/install.sh | sh
```

Windows PowerShell or cmd:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/dip497/hivelock/main/install.ps1 | iex"
```

Picks the right binary for your machine, checks it, and asks which agents to protect. Or take one from [Releases](https://github.com/dip497/hivelock/releases).

## Use

```sh
hivelock import .env       # move the secrets you already have into the vault
hivelock doctor            # check that it's working
hivelock                   # the manager: list, add, lock, stats
```

Then work as usual. `hivelock help` lists every command.

## What you get

| | |
|---|---|
| **Paste a secret in chat** | held back before it's sent, and handed back to you as `{{lock:NAME}}` |
| **Agent runs a command** | real value injected at run time, masked in the output |
| **Agent reads a file with secrets** | masked before the model sees it, and locked away |
| **Old sessions on disk** | scrubbed in place |
| **`hivelock lock NAME`** | human-only: passphrase, agents can't touch it |
| **`hivelock ask NAME`** | the agent must ask you every single time |

Works with **Claude Code · Codex · Copilot CLI · Gemini CLI · Cursor · Qwen Code** on Linux, macOS and Windows.

---

*It is not a sandbox.* Read [what it does and doesn't protect](docs/security.md) — then [usage](docs/usage.md) and [agents](docs/agents.md).

MIT
