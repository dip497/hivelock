# Usage

`hivelock help` lists every command. The ones you'll use:

## Getting secrets in

- **Paste it in chat.** hivelock detects it, saves it with a name (`ghp_…` → `GITHUB_TOKEN`), holds the message back and copies a masked version to your clipboard. Paste that to resend. Add `!nolock` to a message if something isn't really a secret.
- **`hivelock import .env`** imports the secret variables and leaves `PORT`, `NODE_ENV` and similar alone.
- **`hivelock import ~/.ssh/deploy_key`** stores key files (`.pem`, `id_rsa`, `.p12`, service-account JSON, kubeconfig) as file secrets.
- **`hivelock add NAME`** asks for the value with hidden input, or reads it from stdin.

## Using them

The agent writes the name, not the value:

```sh
curl -H "Authorization: Bearer {{lock:GITHUB_TOKEN}}" https://api.github.com/user
ssh -i {{lock:DEPLOY_KEY}} deploy@host    # file secrets become a temp file path
```

Your own apps:

```sh
hivelock run --env DATABASE_URL -- npm run dev
```

## Per-secret access

| Command | Meaning |
|---|---|
| `hivelock open NAME` | agents can use it (default) |
| `hivelock ask NAME` | agents need your OK in their own permission prompt, every time |
| `hivelock lock NAME` | only you, from your terminal, with a passphrase |

## Housekeeping

- **`hivelock scrub`** masks known secrets in sessions that agents already saved to disk.
- **`hivelock scan PATH`** reports secrets in files without storing anything.
- **`hivelock stats`** shows what was blocked, used and masked.
- **Scope:** secrets are global by default. `--project` ties a secret to the current folder, and the same name can hold a different value per project.

On macOS, a downloaded binary may need `xattr -d com.apple.quarantine hivelock` before it will run.
