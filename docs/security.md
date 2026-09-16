# Security

## Storage

Vault folder: `~/.local/share/hivelocker` on Linux, `~/Library/Application Support/hivelocker` on macOS, `%APPDATA%\hivelocker` on Windows.

- `key`: a random 256-bit key, readable only by you.
- `vault.bin`: XChaCha20-Poly1305 encrypted.
- `locked.bin`: locked secrets, encrypted with a key derived from your passphrase (scrypt).
- `audit.jsonl`: event log with names only, never values.

Removed secrets are kept as retired values so they stay masked. `hivelock purge --yes` forgets them.

## What it protects

- Secrets you paste don't reach the model provider (held back, or masked on Copilot).
- The agent works with names; values exist only inside the command that needs them.
- Command output is masked before the model sees it, including base64, URL-encoded and JSON-escaped forms.
- Session files agents keep on disk are scrubbed in place.
- `locked` secrets can't be decrypted by an agent: they need a passphrase typed on a real terminal, and agent shells have none.

## What it doesn't

- **It is not a sandbox.** Any program running as your user can read the key file, or the environment of a running command.
- A command that receives a secret can still leak it in a changed form, for example reversed or partly encoded.
- Masking can confirm a guess: if an agent prints a guessed value and sees it masked, it knows the guess was right.
- Hooks are best effort. A command disguised so the hooks don't recognize it skips their checks.
- Claude Code `@file` attachments skip hooks. They're scrubbed afterwards, but the content was already sent.
- Values under 8 characters aren't masked.
- `ask` approvals are one-time grants issued when the agent asks. A denied request leaves its grant valid for 2 minutes.

Report security issues privately through GitHub security advisories on this repo.
