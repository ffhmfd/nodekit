# Third-party components

The MIT license applies to original NodeKit code. Third-party components retain
their own copyrights and licenses; they are not relicensed under MIT.

## Standalone mihomo core

- Version: **v1.19.33**, unmodified upstream executable, separate from the manager.
- Project and corresponding source: https://github.com/MetaCubeX/mihomo/tree/v1.19.33
- Source archive: https://github.com/MetaCubeX/mihomo/archive/refs/tags/v1.19.33.tar.gz
- License: GNU GPL version 3, https://github.com/MetaCubeX/mihomo/blob/v1.19.33/LICENSE
- Release binaries: https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33
- The release includes `mihomo-v1.19.33-source.tar.gz` and `mihomo-LICENSE` alongside
  the binary bundles. Upstream build scripts and dependency metadata are in that source archive.
- Binary artifact names and SHA256 digests are pinned in `scripts/package.sh`.

## Go manager dependencies

Exact direct and transitive versions and content checksums are in `go.mod` and
`go.sum`. Source and notices can be obtained with `go mod download` and inspected
under `go env GOMODCACHE`. The release's `nodekit-dependencies.tar.gz` preserves
the downloaded module source, including original LICENSE/COPYING/NOTICE files.

Direct dependencies:

| Module | Version | License / source |
|---|---|---|
| github.com/go-acme/lego/v4 | v4.26.0 | MIT — https://github.com/go-acme/lego |
| golang.org/x/sys | v0.37.0 | BSD-3-Clause — https://go.googlesource.com/sys |
| gopkg.in/yaml.v3 | v3.0.1 | MIT and Apache-2.0 notices — https://github.com/go-yaml/yaml/tree/v3.0.1 |
| modernc.org/sqlite | v1.44.3 | BSD-3-Clause; SQLite public-domain notices — https://gitlab.com/cznic/sqlite |

Go runtime and standard library: BSD-3-Clause, https://go.dev/LICENSE.
