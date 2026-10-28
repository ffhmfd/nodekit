package cli

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"nodekit/internal/platform"
	"nodekit/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallRepairsMissingCommandAndPermissions(t *testing.T) {
	root := t.TempDir()
	p := makePaths(root, "")
	archive, sha := testutil.Release(t)
	old := unix.Umask(0077)
	defer unix.Umask(old)
	args := []string{"--file", archive, "--sha256", sha}
	if e := installPackage(context.Background(), p, args, io.Discard); e != nil {
		t.Fatal(e)
	}
	s, e := os.Stat(filepath.Join(p.Opt, "releases"))
	if e != nil || s.Mode().Perm() != 0755 {
		t.Fatal("service cannot traverse releases")
	}
	link := filepath.Join(root, "usr/local/bin/nodekit")
	if e = os.Remove(link); e != nil {
		t.Fatal(e)
	}
	if e = installPackage(context.Background(), p, args, io.Discard); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(link); e != nil {
		t.Fatal("repeat install did not repair command")
	}
}
func TestServeLocksBeforeStateAccess(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(p.Data, 0700)
	os.MkdirAll(p.Etc, 0700)
	os.WriteFile(filepath.Join(p.Etc, "runtime.json"), []byte(`{}`), 0600)
	lock, e := platform.AcquireLock(filepath.Join(p.Data, "manager.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if e = serve(context.Background(), p); e == nil {
		t.Fatal("second instance started")
	}
	if _, e = os.Stat(filepath.Join(p.Data, "state.db")); !os.IsNotExist(e) {
		t.Fatal("second instance touched state before locking")
	}
}
