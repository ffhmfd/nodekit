package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"nodekit/internal/cli"
	"nodekit/internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func exerciseRootRecovery(t *testing.T, invoke func(...string), boot bool) {
	t.Helper()
	old, e := os.Readlink("/opt/nodekit/current")
	if e != nil {
		t.Fatal(e)
	}
	previous, e := os.Readlink("/opt/nodekit/previous")
	if e != nil {
		t.Fatal(e)
	}
	if b, e := exec.Command("systemctl", "stop", "nodekit-manager.service", "nodekit-core.service").CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	snapshot, e := exec.Command("runuser", "-u", "nodekit", "--", "/opt/nodekit/previous/nodekit", "snapshot").Output()
	if e != nil {
		t.Fatal(e)
	}
	if e = platform.WritePrivate("/etc/nodekit/lifecycle/state.db", snapshot); e != nil {
		t.Fatal(e)
	}
	journal, _ := json.Marshal(map[string]string{"Old": old, "New": "releases/interrupted-test", "Previous": previous, "Phase": "switched"})
	if e = platform.WritePrivate("/etc/nodekit/lifecycle/upgrade.json", journal); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "host-file")
	if e = os.WriteFile(outside, []byte("host-file-must-survive"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove("/var/lib/nodekit/state.db"); e != nil {
		t.Fatal(e)
	}
	if b, e := exec.Command("runuser", "-u", "nodekit", "--", "ln", "-s", outside, "/var/lib/nodekit/state.db").CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	os.Remove("/opt/nodekit/current")
	if e = os.Symlink("releases/interrupted-test", "/opt/nodekit/current"); e != nil {
		t.Fatal(e)
	}
	command := exec.Command("/opt/nodekit/previous/nodekit", "recover")
	if boot {
		command = exec.Command("systemctl", "start", "nodekit-core.service")
	}
	if b, e := command.CombinedOutput(); e != nil {
		t.Fatal("offline recovery failed", e, string(b))
	}
	if boot {
		deadline := time.Now().Add(20 * time.Second)
		for {
			var output bytes.Buffer
			if cli.Run(context.Background(), []string{"status"}, bytes.NewReader(nil), &output, &output) == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("boot recovery did not restart manager")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	b, e := os.ReadFile(outside)
	info, _ := os.Stat(outside)
	if e != nil || string(b) != "host-file-must-survive" || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("privileged restore modified outside file")
	}
	current, _ := os.Readlink("/opt/nodekit/current")
	if current != old {
		t.Fatal("old release not restored")
	}
	invoke("status")
}

func exerciseFailedUpgrade(t *testing.T, invoke func(...string)) {
	t.Helper()
	old, _ := os.Readlink("/opt/nodekit/current")
	before, e := os.ReadDir("/opt/nodekit/releases")
	if e != nil {
		t.Fatal(e)
	}
	binary, e := os.ReadFile("/opt/nodekit/current/nodekit")
	if e != nil {
		t.Fatal(e)
	}
	metadata, _ := json.Marshal(map[string]any{"version": "v0.1.99", "arch": runtime.GOARCH, "core_version": "v1.19.33", "schema": 1})
	file := filepath.Join(t.TempDir(), "unhealthy.tar.gz")
	f, e := os.Create(file)
	if e != nil {
		t.Fatal(e)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, b := range map[string][]byte{"nodekit": binary, "mihomo": []byte("#!/bin/sh\ncase \" $* \" in *\" -t \"*) exit 0;; esac\nexit 1\n"), "release.json": metadata} {
		if e = tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(b))}); e != nil {
			t.Fatal(e)
		}
		if _, e = tw.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	tw.Close()
	gz.Close()
	f.Close()
	payload, _ := os.ReadFile(file)
	sum := sha256.Sum256(payload)
	var output bytes.Buffer
	if code := cli.Run(context.Background(), []string{"upgrade", "--file", file, "--sha256", fmt.Sprintf("%x", sum)}, bytes.NewReader(nil), &output, &output); code == 0 {
		t.Fatal("unhealthy core was accepted")
	}
	current, _ := os.Readlink("/opt/nodekit/current")
	if current != old {
		t.Fatal("automatic rollback failed", output.String())
	}
	invoke("status")
	after, e := os.ReadDir("/opt/nodekit/releases")
	if e != nil || len(after) != len(before) {
		t.Fatal("failed release left garbage", len(before), len(after), e)
	}
}
