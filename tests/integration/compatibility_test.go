package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"nodekit/internal/cli"
	"nodekit/internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func exerciseLegacyRejection(t *testing.T) {
	t.Helper()
	archive := os.Getenv("NODEKIT_LEGACY_ARCHIVE")
	if archive == "" {
		t.Fatal("cloudflare lifecycle requires legacy archive")
	}
	payload, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))
	current, _ := os.Readlink("/opt/nodekit/current")
	previous, _ := os.Readlink("/opt/nodekit/previous")
	pid := func() string {
		b, e := exec.Command("systemctl", "show", "nodekit-manager.service", "--property=MainPID", "--value").Output()
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	beforePID := pid()
	if beforePID == "0\n" {
		t.Fatal("manager not active")
	}
	beforeConfig, e := exec.Command("/opt/nodekit/current/nodekit", "config", "export").Output()
	if e != nil {
		t.Fatal(e)
	}
	reject := func(args ...string) {
		t.Helper()
		var out bytes.Buffer
		if code := cli.Run(context.Background(), args, bytes.NewReader(nil), &out, &out); code == 0 {
			t.Fatal("legacy candidate accepted")
		}
		if !bytes.Contains(out.Bytes(), []byte("不支持当前订阅模式")) {
			t.Fatal("unexpected rejection", out.String())
		}
		if pid() != beforePID {
			t.Fatal("capability check stopped service")
		}
		after, _ := os.Readlink("/opt/nodekit/current")
		if after != current {
			t.Fatal("active release changed")
		}
		afterConfig, e := exec.Command("/opt/nodekit/current/nodekit", "config", "export").Output()
		if e != nil || !bytes.Equal(beforeConfig, afterConfig) {
			t.Fatal("rejection changed configuration")
		}
		if _, e = os.Stat("/etc/nodekit/lifecycle/upgrade.json"); !os.IsNotExist(e) {
			t.Fatal("rejection began lifecycle transaction")
		}
	}
	reject("upgrade", "--file", archive, "--sha256", sum)
	target := "releases/legacy-capability-test"
	dest := filepath.Join("/opt/nodekit", target)
	if _, err = platform.ExtractRelease(archive, dest, sum); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dest)
	if err = os.Chmod(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove("/opt/nodekit/previous"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, "/opt/nodekit/previous"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Remove("/opt/nodekit/previous")
		if err := os.Symlink(previous, "/opt/nodekit/previous"); err != nil {
			t.Error(err)
		}
	}()
	reject("rollback")
}
