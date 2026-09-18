#!/usr/bin/env bash
# Cut a release: calendar version YYYY.M.N (the Nth release of that month, from 0), commit,
# wait for CI on main, then tag — which fires release.yml.
#   scripts/release.sh               the computed version
#   scripts/release.sh 2026.9.4      an explicit one
#   scripts/release.sh --dry-run     print the version and stop
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
die() { echo "✗ $*" >&2; exit 1; }

DRY=0; ARG=""
for a in "$@"; do case "$a" in --dry-run) DRY=1 ;; *.*.*) ARG="$a" ;; *) die "unknown arg: $a" ;; esac; done

cur=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
month="$(date -u +%Y).$((10#$(date -u +%m)))"
case "$cur" in "$month".*) next="$month.$(( ${cur##*.} + 1 ))" ;; *) next="$month.0" ;; esac
next="${ARG:-$next}"
[[ "$next" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version: $next"
[ "$(printf '%s\n%s\n' "$cur" "$next" | sort -V | tail -1)" = "$next" ] && [ "$next" != "$cur" ] || die "$next is not newer than $cur"
echo "▸ $cur → $next"
[ "$DRY" = 1 ] && exit 0

[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "not on main"
git diff --quiet && git diff --cached --quiet || die "working tree dirty"
git fetch -q origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main is not in sync with origin"
git rev-parse -q --verify "refs/tags/v$next" >/dev/null && die "tag v$next exists"

sed -i "0,/^version = \".*\"/s//version = \"$next\"/" Cargo.toml
cargo check --quiet   # refreshes Cargo.lock
git commit -qam "Release v$next"
git push -q origin main
sha=$(git rev-parse HEAD)

echo "▸ waiting for CI on $sha"
run=""
for _ in $(seq 30); do
  run=$(gh run list --commit "$sha" --workflow ci.yml --json databaseId -q '.[0].databaseId')
  [ -n "$run" ] && break; sleep 5
done
[ -n "$run" ] || die "CI never started; tag by hand once it passes: git tag -a v$next -m v$next && git push origin v$next"
gh run watch "$run" --exit-status >/dev/null || die "CI failed — main has the version bump, no tag was pushed"

git tag -a "v$next" -m "v$next"
git push -q origin "v$next"
echo "✓ v$next tagged; release.yml is building it"
