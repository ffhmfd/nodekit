package platform

import (
	"context"
	"golang.org/x/sys/unix"
	"nodekit/internal/testutil"
	"os"
	"path/filepath"
	"strings"
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
	var added bool
	f := Firewall{Run: func(_ context.Context, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		if line == "ufw status" {
			return []byte("Status: active\n24446/tcp ALLOW Anywhere # nodekit:tcp:24446\n"), nil
		}
		if strings.Contains(line, "port 2444 comment nodekit:tcp:2444") {
			added = true
		}
		return nil, nil
	}}
	if e := f.Apply(context.Background(), []Binding{{Network: "tcp", Port: 2444}}); e != nil {
		t.Fatal(e)
	}
	if !added {
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
