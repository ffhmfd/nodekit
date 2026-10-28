#!/usr/bin/env bash
set -euo pipefail
archive=''
url=''
sha=''
repo=''
version=''
noninteractive=false
usage() { echo 'Usage: install.sh --repo OWNER/REPO [--version vX.Y.Z] [--non-interactive] | --file ARCHIVE --sha256 SHA256 | --url HTTPS_URL --sha256 SHA256'; }
while (($#)); do
  case "$1" in
    --file) archive=${2:?Missing archive}; shift 2 ;;
    --url) url=${2:?Missing HTTPS URL}; shift 2 ;;
    --sha256) sha=${2:?Missing SHA256}; shift 2 ;;
    --repo) repo=${2:?Missing OWNER/REPO}; shift 2 ;;
    --version) version=${2:?Missing version}; shift 2 ;;
    --non-interactive) noninteractive=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [[ -n $repo ]]; then
  [[ $repo =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ && $repo != *..* ]] || { echo 'Invalid OWNER/REPO' >&2; exit 2; }
  [[ -z $archive && -z $url && -z $sha ]] || { echo '--repo cannot be combined with --file/--url/--sha256' >&2; exit 2; }
  [[ -z $version || $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid release version' >&2; exit 2; }
  if [[ ! -t 0 && $noninteractive == false ]]; then echo 'No terminal: pass --non-interactive to install binaries, then run sudo nodekit setup in a terminal' >&2; exit 2; fi
  case $(uname -m) in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo 'Unsupported architecture (requires amd64/arm64)' >&2; exit 2 ;;
  esac
else
  [[ -z $version ]] || { echo '--version requires --repo' >&2; exit 2; }
  [[ $sha =~ ^[a-f0-9]{64}$ ]] || { echo 'A trusted SHA256 checksum is required' >&2; exit 2; }
  [[ -n $archive && -z $url || -z $archive && -n $url ]] || { echo 'Supply exactly one of --file or --url' >&2; exit 2; }
fi
umask 077
tmp=$(mktemp -d /var/tmp/nodekit-install-XXXXXXXX)
trap 'rm -rf -- "$tmp"' EXIT
download() { curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 2 "$1" -o "$2"; }
if [[ -n $repo ]]; then
  if [[ -z $version ]]; then
    download "https://api.github.com/repos/$repo/releases/latest" "$tmp/latest.json"
    version=$(grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"\\]*"' "$tmp/latest.json" | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/')
    [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Latest stable release has an invalid version' >&2; exit 2; }
  fi
  asset="nodekit-$version-linux-$arch.tar.gz"
  base="https://github.com/$repo/releases/download/$version"
  download "$base/SHA256SUMS" "$tmp/SHA256SUMS"
  sha=$(awk -v file="$asset" 'NF == 2 && ($2 == file || $2 == "*" file) {print $1}' "$tmp/SHA256SUMS")
  [[ $sha =~ ^[a-f0-9]{64}$ ]] || { echo 'Release checksum missing or ambiguous for architecture' >&2; exit 2; }
  url="$base/$asset"
fi
if [[ -n $url ]]; then
  [[ $url == https://* ]] || { echo 'HTTPS required' >&2; exit 2; }
  download "$url" "$tmp/release.tar.gz"
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
if [[ -x /opt/nodekit/current/nodekit ]]; then
  echo '已有安装；升级请使用 nodekit upgrade --file <包> --sha256 <校验和>。'
  if [[ -t 0 && $noninteractive == false ]]; then /opt/nodekit/current/nodekit; fi
  exit 0
fi
"$tmp/nodekit" install --file "$tmp/release.tar.gz" --sha256 "$sha"
if [[ -n $repo && -t 0 && $noninteractive == false ]]; then
  if [[ -f /var/lib/nodekit/state.db || -f /etc/nodekit/setup.json || -f /etc/nodekit/host.json ]]; then
    /opt/nodekit/current/nodekit
  else
    /opt/nodekit/current/nodekit setup
  fi
else
  echo '程序已安装。首次配置运行 sudo nodekit setup；保留数据重装运行 sudo nodekit resume。'
fi
