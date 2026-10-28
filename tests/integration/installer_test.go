package integration

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerRejectsChecksumAndCleansScratch(t *testing.T) {
	if _, e := exec.LookPath("bash"); e != nil {
		t.Skip("bash required")
	}
	file := filepath.Join(t.TempDir(), "archive with spaces.tar.gz")
	if e := os.WriteFile(file, []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	before, e := filepath.Glob("/var/tmp/nodekit-install-*")
	if e != nil {
		t.Fatal(e)
	}
	known := map[string]bool{}
	for _, p := range before {
		known[p] = true
	}
	script := filepath.Join("..", "..", "install.sh")
	sum := sha256.Sum256([]byte("different"))
	out, e := exec.Command("bash", script, "--file", file, "--sha256", fmt.Sprintf("%x", sum)).CombinedOutput()
	if e == nil || !strings.Contains(string(out), "FAILED") {
		t.Fatalf("checksum failure not detected: %v %s", e, out)
	}
	after, _ := filepath.Glob("/var/tmp/nodekit-install-*")
	for _, p := range after {
		if !known[p] {
			t.Fatalf("installer scratch left behind: %s", p)
		}
	}
}
