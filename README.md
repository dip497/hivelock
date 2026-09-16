# hivelock

I kept handing secrets to my coding agent. Paste the API key into the prompt, or just say "read it from my `.env`". It works, and now that key sits with the model provider, in the session log on disk, and in whatever output the agent prints next.

hivelock stops that. Paste a secret and the message is held back before it's sent: the secret goes into a local encrypted vault, and you resend with `{{lock:STRIPE_SECRET_KEY}}`. The agent only ever works with that name. When it runs a command, hivelock fills in the real value and masks it again in the output.

## Install

Download a binary from [Releases](https://github.com/dip497/hivelock/releases) and put it on your `PATH`, or:

```sh
cargo install --git https://github.com/dip497/hivelock
```

## Use

```sh
hivelock install claude    # or: codex, copilot, gemini, cursor, qwen
hivelock import .env       # move existing secrets into the vault
hivelock doctor            # check that it's working
```

Then work as usual. Run `hivelock` on its own for a small manager, or `hivelock help` for every command.

Works on Linux, macOS and Windows. It is not a sandbox, so read [what it does and doesn't protect](docs/security.md).

[Docs](docs/) · MIT
