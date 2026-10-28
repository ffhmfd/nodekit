#!/usr/bin/env bash
set -euo pipefail
archive=''
url=''
sha=''
while (($#)); do
  case "$1" in
    --file) archive=${2:?Missing archive}; shift 2 ;;
    --url) url=${2:?Missing HTTPS URL}; shift 2 ;;
    --sha256) sha=${2:?Missing SHA256}; shift 2 ;;
    *) echo 'Usage: install.sh --file release.tar.gz --sha256 SHA256 (or --url HTTPS_URL)' >&2; exit 2 ;;
  esac
done
[[ $sha =~ ^[a-f0-9]{64}$ ]] || { echo 'A trusted SHA256 checksum is required' >&2; exit 2; }
[[ -n $archive || -n $url ]] || { echo 'Supply --file or --url' >&2; exit 2; }
umask 077
tmp=$(mktemp -d /var/tmp/nodekit-install-XXXXXXXX)
trap 'rm -rf -- "$tmp"' EXIT
if [[ -n $url ]]; then
  [[ $url == https://* ]] || { echo 'HTTPS required' >&2; exit 2; }
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --retry 2 "$url" -o "$tmp/release.tar.gz"
else
  cp -- "$archive" "$tmp/release.tar.gz"
fi
printf '%s  %s\n' "$sha" "$tmp/release.tar.gz" | sha256sum -c -
[[ $EUID -eq 0 ]] || { echo 'Run installation as root' >&2; exit 1; }
tar -tzf "$tmp/release.tar.gz" > "$tmp/entries"
[[ $(wc -l < "$tmp/entries") -eq 3 ]] || { echo 'Invalid release entries' >&2; exit 1; }
[[ $(sort -u "$tmp/entries" | wc -l) -eq 3 ]] || exit 1
if grep -Ev '^(nodekit|mihomo|release.json)$' "$tmp/entries"; then echo 'Unsafe archive path' >&2; exit 1; fi
tar -tvzf "$tmp/release.tar.gz" | awk '$1 !~ /^-/ || $3 > 134217728 {bad=1} END {exit bad}'
tar -xzf "$tmp/release.tar.gz" -C "$tmp" --no-same-owner --no-same-permissions nodekit
chmod 700 "$tmp/nodekit"
"$tmp/nodekit" install --file "$tmp/release.tar.gz" --sha256 "$sha"
