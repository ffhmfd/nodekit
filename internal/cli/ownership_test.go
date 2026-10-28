package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedResourcesRefuseReplacement(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(p.Etc, 0700)
	path := filepath.Join(p.Root, "etc/systemd/system/nodekit-core.service")
	os.MkdirAll(filepath.Dir(path), 0700)
	want := []byte("our unit")
	m := hostManifest{UID: os.Getuid(), GID: os.Getgid(), Files: map[string]string{path: hashBytes(want)}}
	if e := saveHost(p, m); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(path, want, 0644)
	if e := checkOwnedFiles(m); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(path, []byte("replacement"), 0644)
	if e := checkOwnedFiles(m); e == nil {
		t.Fatal("replacement unit adopted")
	}
}
