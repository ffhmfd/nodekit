package platform

import (
	"context"
	"golang.org/x/sys/unix"
	"nodekit/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestReleasePermissionsIgnoreRestrictiveUmask(t *testing.T) {
	archive, sha := testutil.Release(t)
	old := unix.Umask(0077)
	defer unix.Umask(old)
	dest := filepath.Join(t.TempDir(), "release")
	if _, e := ExtractRelease(archive, dest, sha); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"nodekit", "mihomo"} {
		s, e := os.Stat(filepath.Join(dest, name))
		if e != nil || s.Mode().Perm() != 0755 {
			t.Fatalf("service cannot execute %s: %v %v", name, s, e)
		}
	}
}
func TestUFWExactPortOwnership(t *testing.T) {
	s := &familyFirewall{ufw: true, rules: map[string]bool{"tcp 24446 any nodekit:tcp:24446": true}}
	f := Firewall{Run: s.run}
	if e := f.Apply(context.Background(), []Binding{{Network: "tcp", Port: 2444}}); e != nil {
		t.Fatal(e)
	}
	if !s.rules["tcp 2444 0.0.0.0/0 nodekit:tcp:2444"] {
		t.Fatal("port prefix collision skipped new rule")
	}
}
func TestExclusiveProcessLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manager.lock")
	a, e := AcquireLock(path)
	if e != nil {
		t.Fatal(e)
	}
	if b, e := AcquireLock(path); e == nil {
		b.Close()
		t.Fatal("second instance entered")
	}
	a.Close()
	b, e := AcquireLock(path)
	if e != nil {
		t.Fatal("lock not released", e)
	}
	b.Close()
}
