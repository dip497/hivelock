# hivelock

I kept handing secrets to my coding agent. Paste the API key into the prompt, or just say "read it from my `.env`". It works, and now that key sits with the model provider, in the session log on disk, and in whatever output the agent prints next.

hivelock stops that. Paste a secret and the message is held back before it's sent: the secret goes into a local encrypted vault, and you resend with `{{lock:STRIPE_SECRET_KEY}}`. The agent only ever works with that name. When it runs a command, hivelock fills in the real value and masks it again in the output.

## Install

macOS, Linux, WSL:

```sh
curl -fsSL https://raw.githubusercontent.com/dip497/hivelock/main/install.sh | sh
```

Windows (cmd or PowerShell):

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/dip497/hivelock/main/install.ps1 | iex"
```

No Rust needed. The installer downloads the binary for your machine, checks it, and then asks which agents to protect (all are ticked by default). You can also grab a binary from [Releases](https://github.com/dip497/hivelock/releases) or build it with `cargo install --git https://github.com/dip497/hivelock`.

## Use

```sh
hivelock setup             # pick agents again any time
hivelock import .env       # move existing secrets into the vault
hivelock doctor            # check that it's working
```

Then work as usual. Run `hivelock` on its own for a small manager, or `hivelock help` for every command.

Works on Linux, macOS and Windows. It is not a sandbox, so read [what it does and doesn't protect](docs/security.md).

[Docs](docs/) · MIT
