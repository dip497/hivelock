#!/bin/sh
# Install hivelock from GitHub releases (Linux, macOS).
#   curl -fsSL https://raw.githubusercontent.com/dip497/hivelock/main/install.sh | sh
# Env: HIVELOCK_VERSION (default: latest), HIVELOCK_BIN_DIR (default: ~/.local/bin), HIVELOCK_NO_SETUP=1
set -eu

repo="dip497/hivelock"
bin_dir="${HIVELOCK_BIN_DIR:-$HOME/.local/bin}"

fail() { echo "hivelock install: $*" >&2; exit 1; }

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    # Git Bash etc. on Windows: hand over to the PowerShell installer
    ps1="${HIVELOCK_INSTALL_PS1:-https://raw.githubusercontent.com/$repo/main/install.ps1}"
    if [ -f "$ps1" ]; then
      exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$ps1"
    fi
    exec powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm '$ps1' | iex" ;;
  Linux) os="unknown-linux-musl" ;;
  Darwin) os="apple-darwin" ;;
  *) fail "unsupported OS $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  arm64 | aarch64) arch="aarch64" ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac

if command -v curl > /dev/null; then
  fetch() { curl -fsSL "$1" -o "$2"; }
  latest() { curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest"; }
elif command -v wget > /dev/null; then
  fetch() { wget -qO "$2" "$1"; }
  latest() { wget -S --spider "https://github.com/$repo/releases/latest" 2>&1 | sed -n 's/^ *Location: *//p' | tail -1; }
else
  fail "needs curl or wget"
fi

version="${HIVELOCK_VERSION:-}"
if [ -z "$version" ]; then
  version="$(latest | sed 's#.*/tag/##' | tr -d '\r')"
  [ -n "$version" ] || fail "could not find the latest release"
fi

name="hivelock-$version-$arch-$os"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading $name"
fetch "https://github.com/$repo/releases/download/$version/$name.tar.gz" "$tmp/$name.tar.gz" || fail "download failed ($version for $arch-$os)"
fetch "https://github.com/$repo/releases/download/$version/SHA256SUMS" "$tmp/SHA256SUMS" || fail "checksum download failed"

expected="$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
if command -v sha256sum > /dev/null; then
  actual="$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)"
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "checksum mismatch, not installing"

tar xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$bin_dir"
# write beside it and rename over: works even while hivelock is running (hooks, TUI)
cp "$tmp/$name/hivelock" "$bin_dir/.hivelock.new"
chmod 755 "$bin_dir/.hivelock.new"
mv -f "$bin_dir/.hivelock.new" "$bin_dir/hivelock"

echo "installed $("$bin_dir/hivelock" --version) to $bin_dir/hivelock"
case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) echo "add it to your PATH:  export PATH=\"$bin_dir:\$PATH\"" ;;
esac
# onboarding needs a keyboard: under `curl | sh` stdin is the script, so read keys from the tty
if [ -z "${HIVELOCK_NO_SETUP:-}" ] && [ -t 1 ] && (: < /dev/tty) 2> /dev/null; then
  "$bin_dir/hivelock" setup < /dev/tty
else
  echo "next: hivelock setup"
fi
