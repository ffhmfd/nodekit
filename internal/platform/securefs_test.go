package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "host-file")
	if e := os.WriteFile(outside, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(root, "state.db")); e != nil {
		t.Fatal(e)
	}
	if e := RestoreAtomic(root, "state.db", []byte("restored"), os.Getuid(), os.Getgid()); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "preserve" {
		t.Fatal("followed hostile database symlink")
	}
	b, _ = os.ReadFile(filepath.Join(root, "state.db"))
	if string(b) != "restored" {
		t.Fatal("database not restored")
	}
	if e := RestoreAtomic(root, "../escape", nil, os.Getuid(), os.Getgid()); e == nil {
		t.Fatal("escaped restore root")
	}
}
func TestPrivateFileRejectsSymlinkAndWritableParent(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "other")
	os.WriteFile(outside, []byte("secret"), 0600)
	path := filepath.Join(dir, "backup")
	os.Symlink(outside, path)
	if _, e := ReadPrivate(path); e == nil {
		t.Fatal("followed backup symlink")
	}
	os.Remove(path)
	if e := WritePrivate(path, []byte("backup")); e != nil {
		t.Fatal(e)
	}
	b, e := ReadPrivate(path)
	if e != nil || string(b) != "backup" {
		t.Fatal(e)
	}
	os.Chmod(dir, 0777)
	if _, e = ReadPrivate(path); e == nil {
		t.Fatal("accepted writable backup directory")
	}
}

func TestClaimRejectsSymlinkOwnershipMarker(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "marker")
	if e := os.WriteFile(outside, []byte("nodekit-v1\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(dir, ".nodekit-owned")); e != nil {
		t.Fatal(e)
	}
	if e := Claim(dir); e == nil {
		t.Fatal("adopted directory through symlink marker")
	}
}
