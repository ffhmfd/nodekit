package cli

import (
	"context"
	"fmt"
	"io"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// External service commands are doubled only inside the marked chroot. The
// actual resume code, private files, permissions and recovery messages run.
func init() {
	if os.Getenv("NODEKIT_INSTALL_SANDBOX") != "1" {
		return
	}
	if _, err := os.Stat("/.nodekit-install-sandbox"); err != nil {
		return
	}
	switch filepath.Base(os.Args[0]) {
	case "nodekit":
		if len(os.Args) == 2 && os.Args[1] == "capabilities" {
			fmt.Println(`{"subscription_modes":["direct","cloudflare"],"features":["node-names-v1","managed-dns-v1","purge-v1","ipv6-nodes-v1"]}`)
			os.Exit(0)
		}
		os.Exit(2)
	case "runuser":
		switch os.Args[len(os.Args)-1] {
		case "inspect":
			b, err := os.ReadFile("/etc/nodekit/test-config.json")
			if err != nil {
				os.Exit(2)
			}
			fmt.Print(string(b))
			os.Exit(0)
		case "prepare":
			os.Exit(0)
		}
		os.Exit(2)
	case "systemd-tmpfiles":
		os.Exit(0)
	case "systemctl":
		if len(os.Args) > 1 && os.Args[1] == "enable" {
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func TestInstallResumeSandboxChild(t *testing.T) {
	if os.Getenv("NODEKIT_INSTALL_SANDBOX") != "1" {
		t.Skip("chroot child only")
	}
	if _, err := os.Stat("/.nodekit-install-sandbox"); err != nil {
		t.Fatal(err)
	}
	p := makePaths("/", "")
	before, err := os.ReadFile(filepath.Join(p.Etc, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = resume(context.Background(), p)
	if err == nil || !strings.Contains(err.Error(), "防火墙预检") || !strings.Contains(err.Error(), "resume --firewall manual") {
		t.Fatalf("got %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(p.Etc, "runtime.json"))
	if string(before) != string(after) {
		t.Fatal("unsupported auto changed runtime configuration")
	}
	err = resumeCommand(context.Background(), p, []string{"--firewall", "manual"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "安装并启动服务") {
		t.Fatalf("manual did not reach service phase: %v", err)
	}
	rt, err := p.runtime()
	if err != nil || rt.Firewall != "manual" {
		t.Fatal("manual mode not saved", rt.Firewall, err)
	}
	err = execute(context.Background(), p, []string{"subscription"}, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "安装未完成") || !strings.Contains(err.Error(), "安装并启动服务") || strings.Contains(err.Error(), "dial unix") {
		t.Fatalf("lost service failure stage: %v", err)
	}
	// The committed database wins over an obsolete wizard candidate. This
	// exercises setup --resume's actual delegation to the same recovery path.
	if err := writeJSON(filepath.Join(p.Etc, "setup.json"), setupInput{Firewall: "auto"}); err != nil {
		t.Fatal(err)
	}
	err = setupCommand(context.Background(), p, []string{"--resume"}, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "安装并启动服务") {
		t.Fatalf("saved wizard did not preserve committed manual mode: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.Etc, "setup-config.json")); !os.IsNotExist(err) {
		t.Fatal("committed recovery rewrote wizard config", err)
	}
}

func TestInstallResumeInIsolatedFilesystem(t *testing.T) {
	if os.Getenv("NODEKIT_TEST_CHROOT") != "1" {
		t.Skip("explicit root chroot opt-in required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("chroot needs root")
	}
	root := t.TempDir()
	p := makePaths(root, "")
	for _, dir := range []string{p.Etc, p.Data, p.Run, p.Opt} {
		if err := platform.Claim(dir); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "dev"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		".nodekit-install-sandbox": "test\n",
		"dev/null":                 "",
		"etc/passwd":               "root:x:0:0:root:/root:/bin/sh\nnodekit:x:950:950::/var/lib/nodekit:/usr/sbin/nologin\n",
		"etc/group":                "root:x:0:\nnodekit:x:950:\n",
		"var/lib/nodekit/state.db": "published configuration marker\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveHost(p, hostManifest{UID: 950, GID: 950, InitPhase: "configured", Files: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(p.Etc, "runtime.json"), runtimeConfig{Firewall: "auto"}); err != nil {
		t.Fatal(err)
	}
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.Domain, c.Address = "node.example.com", "8.8.8.8"
	if err := writeJSON(filepath.Join(p.Etc, "test-config.json"), c); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/test"), b, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(p.Opt, "current"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "bin/test"), filepath.Join(p.Opt, "current/nodekit")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"runuser", "systemctl", "systemd-tmpfiles"} {
		if err := os.Link(filepath.Join(root, "bin/test"), filepath.Join(root, "bin", command)); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("/bin/test", "-test.run=^TestInstallResumeSandboxChild$", "-test.v")
	cmd.Env = append(os.Environ(), "NODEKIT_INSTALL_SANDBOX=1", "PATH=/bin")
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
	cmd.Dir = "/"
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated resume failed: %v\n%s", err, out)
	}
}
