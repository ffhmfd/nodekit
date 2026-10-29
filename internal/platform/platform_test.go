package platform

import (
	"context"
	"net"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortConflictAndOwnedDirectory(t *testing.T) {
	l, e := net.Listen("tcp4", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c, _ := model.New()
	c.Protocols[0].Port = l.Addr().(*net.TCPAddr).Port
	if e := CheckPorts(c, nil); e == nil {
		t.Fatal("occupied port accepted")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "existing")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "foreign"), []byte("keep"), 0600)
	if e := Claim(dir); e == nil {
		t.Fatal("claimed foreign directory")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "foreign"))
	if string(b) != "keep" {
		t.Fatal("foreign data modified")
	}
	owned := filepath.Join(root, "owned")
	if e := Claim(owned); e != nil {
		t.Fatal(e)
	}
	if e := Claim(owned); e != nil {
		t.Fatal("not idempotent", e)
	}
}
func TestFirewallOwnsOnlyPreciseRules(t *testing.T) {
	var commands []string
	state := &familyFirewall{rules: map[string]bool{}}
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		s := strings.Join(args, " ")
		commands = append(commands, s)
		return state.run(ctx, args...)
	}
	f := Firewall{Run: run}
	b := []Binding{{Network: "tcp", Port: 24441}, {Network: "udp", Port: 24442}}
	if e := f.Apply(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "-I INPUT 1") || !strings.Contains(joined, "nodekit:") {
		t.Fatal(joined)
	}
	if strings.Contains(joined, "-F") || strings.Contains(joined, "-P INPUT") {
		t.Fatal("global policy mutation")
	}
	commands = nil
	if e := f.Remove(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	for _, s := range commands {
		if strings.Contains(s, " -D ") && !strings.Contains(s, "nodekit:") {
			t.Fatal("unowned deletion")
		}
	}
}
