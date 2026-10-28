package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Static test executable doubles only the external host commands, inside chroot.
func init() {
	if os.Getenv("NODEKIT_PURGE_SANDBOX") != "1" {
		return
	}
	if _, err := os.Stat("/.nodekit-test-sandbox"); err != nil {
		return
	}
	name := filepath.Base(os.Args[0])
	if name == "runuser" && len(os.Args) >= 6 {
		if err := syscall.Exec(os.Args[4], os.Args[4:], os.Environ()); err != nil {
			os.Exit(2)
		}
	}
	if name == "nodekit" && len(os.Args) > 1 {
		if os.Args[1] == "capabilities" {
			fmt.Println(`{"subscription_modes":["direct","cloudflare"],"features":["node-names-v1","managed-dns-v1","purge-v1"]}`)
			os.Exit(0)
		}
		if os.Args[1] == "prepare" {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if name != "systemctl" && name != "userdel" && name != "groupdel" {
		return
	}
	if name == "systemctl" {
		if len(os.Args) > 1 && os.Args[1] == "daemon-reload" {
			if _, err := os.Stat("/fail-once"); err == nil {
				os.Remove("/fail-once")
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
	file := "/etc/passwd"
	if name == "groupdel" {
		file = "/etc/group"
	}
	b, err := os.ReadFile(file)
	if err != nil {
		os.Exit(2)
	}
	var kept []string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "nodekit:") {
			kept = append(kept, line)
		}
	}
	if os.WriteFile(file, []byte(strings.Join(kept, "\n")), 0644) != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestPurgeSandboxChild(t *testing.T) {
	if os.Getenv("NODEKIT_PURGE_SANDBOX") != "1" {
		t.Skip("chroot child only")
	}
	if _, err := os.Stat("/.nodekit-test-sandbox"); err != nil {
		t.Fatal("missing sandbox marker")
	}
	p := makePaths("/", "")
	if err := purgeCommand(context.Background(), p, io.Discard); err == nil {
		t.Fatal("expected interrupted daemon-reload")
	}
	if _, err := os.Stat("/root/nodekit-cloudflare.token"); err != nil {
		t.Fatal("credentials lost on interrupted purge")
	}
	if err := purgeCommand(context.Background(), p, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.Opt, p.Etc, p.Data, p.Run, "/root/nodekit-cloudflare.token", "/usr/local/bin/nodekit"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("owned resource remains", path, err)
		}
	}
	for _, file := range []string{"/etc/passwd", "/etc/group"} {
		b, _ := os.ReadFile(file)
		if strings.Contains(string(b), "nodekit:") {
			t.Fatal("account remains")
		}
	}
	if b, err := os.ReadFile("/outside-token"); err != nil || string(b) != "keep" {
		t.Fatal("external source removed")
	}
}

func TestPurgeHostInIsolatedFilesystem(t *testing.T) {
	if os.Getenv("NODEKIT_TEST_CHROOT") != "1" {
		t.Skip("explicit root chroot opt-in required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required for isolated chroot")
	}
	root := t.TempDir()
	p := makePaths(root, "")
	for _, dir := range []string{p.Etc, p.Opt, p.Data, p.Run} {
		if err := platform.Claim(dir); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string, mode os.FileMode) {
		t.Helper()
		file := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(file), 0755)
		if err := os.WriteFile(file, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("/.nodekit-test-sandbox", "", 0600)
	write("/fail-once", "", 0600)
	write("/dev/null", "", 0666)
	write("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnodekit:x:999:999:nodekit:/var/lib/nodekit:/bin/false\n", 0644)
	write("/etc/group", "root:x:0:\nnodekit:x:999:\n", 0644)
	write("/root/nodekit-cloudflare.token", "test-secret", 0600)
	write("/etc/nodekit/cloudflare.token", "test-secret", 0600)
	write("/outside-token", "keep", 0600)
	if err := os.Chown(p.Run, 999, 999); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p.Run, 0700)
	m := hostManifest{UID: 999, GID: 999, PurgePhase: "dns_removed", Files: map[string]string{}}
	for _, name := range []string{"nodekit-core.service", "nodekit-manager.service"} {
		file := "/etc/systemd/system/" + name
		write(file, "owned", 0644)
		m.Files[file] = hashBytes([]byte("owned"))
	}
	if err := saveHost(p, m); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"testbin", "bin/systemctl", "bin/userdel", "bin/groupdel"} {
		file := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(file), 0755)
		if err = os.WriteFile(file, binary, 0755); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(root, "usr/local/bin"), 0755)
	os.Symlink("/opt/nodekit/current/nodekit", filepath.Join(root, "usr/local/bin/nodekit"))
	cmd := exec.Command("/testbin", "-test.run=^TestPurgeSandboxChild$", "-test.v")
	cmd.Dir = "/"
	cmd.Env = []string{"NODEKIT_PURGE_SANDBOX=1", "PATH=/bin", "HOME=/root"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated host purge: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestLegacyRecoverySandboxChild(t *testing.T) {
	if os.Getenv("NODEKIT_PURGE_SANDBOX") != "1" {
		t.Skip("chroot child only")
	}
	if _, err := os.Stat("/.nodekit-test-sandbox"); err != nil {
		t.Fatal(err)
	}
	p := makePaths("/", "")
	if err := recoverUpgrade(context.Background(), p, true); err != nil {
		t.Fatal("offline legacy recovery failed", err)
	}
	current, _ := os.Readlink("/opt/nodekit/current")
	if current != "releases/old" {
		t.Fatal("old release not restored")
	}
	db, err := p.db()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r, err := db.Load()
	if err != nil || r.Config.Name != "saved-host" {
		t.Fatal("snapshot not restored", err)
	}
	if b, _ := os.ReadFile("/outside"); string(b) != "keep" {
		t.Fatal("restore followed live database symlink")
	}
}

func TestLegacyRecoveryInIsolatedFilesystem(t *testing.T) {
	if os.Getenv("NODEKIT_TEST_CHROOT") != "1" {
		t.Skip("explicit root chroot opt-in required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	root := t.TempDir()
	p := makePaths(root, "")
	write := func(name string, b []byte, mode os.FileMode) {
		t.Helper()
		file := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(file), 0755)
		if err := os.WriteFile(file, b, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{p.Etc, p.Opt, p.Data} {
		if err := platform.Claim(dir); err != nil {
			t.Fatal(err)
		}
	}
	write("/.nodekit-test-sandbox", nil, 0600)
	write("/dev/null", nil, 0666)
	write("/etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\nnodekit:x:999:999:nodekit:/var/lib/nodekit:/bin/false\n"), 0644)
	write("/etc/group", []byte("root:x:0:\nnodekit:x:999:\n"), 0644)
	if err := saveHost(p, hostManifest{UID: 999, GID: 999}); err != nil {
		t.Fatal(err)
	}
	c, _ := model.New()
	c.SetDisplayDefaults("saved-host", "JP")
	os.MkdirAll(lifecycleDir(p), 0700)
	if err := store.Initialize(filepath.Join(lifecycleDir(p), "state.db"), store.Record{Config: c}); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"Old": "releases/old", "New": "releases/broken", "Previous": "releases/old", "Phase": "switched"})
	if err := platform.WritePrivate(filepath.Join(lifecycleDir(p), "upgrade.json"), b); err != nil {
		t.Fatal(err)
	}
	write("/outside", []byte("keep"), 0600)
	os.Symlink("/outside", filepath.Join(p.Data, "state.db"))
	os.Symlink("releases/broken", filepath.Join(p.Opt, "current"))
	os.Symlink("releases/old", filepath.Join(p.Opt, "previous"))
	self, _ := os.Executable()
	binary, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/testbin", "/bin/systemctl", "/bin/runuser", "/opt/nodekit/releases/old/nodekit"} {
		write(name, binary, 0755)
	}
	cmd := exec.Command("/testbin", "-test.run=^TestLegacyRecoverySandboxChild$", "-test.v")
	cmd.Dir = "/"
	cmd.Env = []string{"NODEKIT_PURGE_SANDBOX=1", "PATH=/bin", "HOME=/root"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated recovery: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
