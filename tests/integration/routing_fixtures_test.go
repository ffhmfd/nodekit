package integration

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Existing integration tests also check full subscriptions in fresh core homes.
// Seed those homes without rewriting their YAML or allowing cold Geo downloads.
// The wrapper is test-process-local and only writes beneath this run's TMPDIR.
func TestMain(m *testing.M) {
	cleanup, err := routingOfflineCore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "offline routing fixtures:", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func routingOfflineCore() (func(), error) {
	bin := os.Getenv("NODEKIT_CORE_BIN")
	if bin == "" || runtime.GOOS != "linux" {
		return func() {}, nil
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("resolve NODEKIT_CORE_BIN %q: %w", bin, err)
	}
	bin, err = filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "nk-routing-fixtures-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	for name, data := range routingGeoFixtures() {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			cleanup()
			return nil, err
		}
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	wrapper := "#!/bin/sh\nset -eu\nhome=\nprevious=\nfor arg do\n" +
		"  if [ \"$previous\" = -d ]; then home=$arg; fi\n  previous=$arg\ndone\n" +
		"if [ -n \"$home\" ]; then\n  case \"$home\" in\n    " + quote(os.TempDir()+string(os.PathSeparator)) + "*) ;;\n" +
		"    *) echo 'core fixture home outside test TMPDIR' >&2; exit 1;;\n  esac\n  mkdir -p \"$home\"\n" +
		"  for asset in GeoSite.dat Country.mmdb; do\n    if [ ! -e \"$home/$asset\" ]; then cp " + quote(dir) + "/\"$asset\" \"$home/$asset\"; fi\n  done\nfi\n" +
		"exec " + quote(bin) + " \"$@\"\n"
	path := filepath.Join(dir, "offline-core")
	if err := os.WriteFile(path, []byte(wrapper), 0700); err != nil {
		cleanup()
		return nil, err
	}
	if err := os.Setenv("NODEKIT_CORE_BIN", path); err != nil {
		cleanup()
		return nil, err
	}
	fmt.Println("integration: generated offline Geo fixtures enabled (test-local core homes; original YAML unchanged)")
	return cleanup, nil
}

// GeoSite uses the pinned core's router/config.proto wire format: lists
// contain field 1 entries; entries contain field 1 country and field 2 records.
// Domain type 2 is a suffix.
// CN is required by core asset verification even when no GEOSITE,CN rule exists.
func routingGeoFixtures() map[string][]byte {
	field := func(tag byte, value []byte) []byte {
		b := []byte{tag}
		b = binary.AppendUvarint(b, uint64(len(value)))
		return append(b, value...)
	}
	var sites []byte
	for _, item := range []struct{ code, domain string }{{"CN", "cn.example"}, {"youtube", "youtube.com"}, {"openai", "openai.com"}} {
		domain := append([]byte{0x08, 2}, field(0x12, []byte(item.domain))...)
		entry := append(field(0x0a, []byte(item.code)), field(0x12, domain)...)
		sites = append(sites, field(0x0a, entry)...)
	}
	return map[string][]byte{"GeoSite.dat": sites, "Country.mmdb": routingEmptyMMDB()}
}

// Minimal MaxMind DB v2: one 24-bit search node, both children point to the
// empty-record sentinel (node_count=1). No IP is assigned a country. This checks
// the ORIGINAL template's default MMDB backend, not a geodata-mode substitution.
// No third-party database, network download, or new encoder dependency is needed.
func routingEmptyMMDB() []byte {
	text := func(s string) []byte { return append([]byte{0x40 | byte(len(s))}, []byte(s)...) }
	metadata := []byte{0xe9} // map of nine metadata fields
	for _, item := range []struct {
		key   string
		value []byte
	}{
		{"node_count", []byte{0xc1, 1}}, {"record_size", []byte{0xa1, 24}},
		{"ip_version", []byte{0xa1, 4}}, {"database_type", text("GeoIP2-Country")},
		{"languages", append([]byte{1, 4}, text("en")...)}, // extended type 11 (array)
		{"binary_format_major_version", []byte{0xa1, 2}}, {"binary_format_minor_version", []byte{0xa0}},
		{"build_epoch", []byte{0, 2}}, // extended type 9 (uint64), zero
		{"description", append(append([]byte{0xe1}, text("en")...), text("NodeKit offline test")...)},
	} {
		metadata = append(metadata, text(item.key)...)
		metadata = append(metadata, item.value...)
	}
	b := []byte{0, 0, 1, 0, 0, 1}
	b = append(b, make([]byte, 16)...)
	b = append(b, []byte("\xab\xcd\xefMaxMind.com")...)
	return append(b, metadata...)
}
