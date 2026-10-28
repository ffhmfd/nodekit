package platform

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectUnsafeRelease(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "nested/file"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.tgz")
		f, e := os.Create(path)
		if e != nil {
			t.Fatal(e)
		}
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: 1})
		_, _ = tw.Write([]byte("x"))
		tw.Close()
		gz.Close()
		f.Close()
		b, _ := os.ReadFile(path)
		sum := sha256.Sum256(b)
		if _, e := ExtractRelease(path, filepath.Join(dir, "unpack"), fmt.Sprintf("%x", sum)); e == nil {
			t.Fatal("unsafe archive accepted", name)
		}
	}
}
func TestChecksumMismatchDoesNotCreateDestination(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "archive")
	os.WriteFile(path, []byte("not a release"), 0600)
	dest := filepath.Join(root, "release")
	if _, e := ExtractRelease(path, dest, "deadbeef"); e == nil {
		t.Fatal("bad checksum accepted")
	}
	if _, e := os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("destination created before validation")
	}
}
