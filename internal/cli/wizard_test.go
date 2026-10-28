package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"nodekit/internal/terminal"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWizardCollectsCandidateWithoutSideEffects(t *testing.T) {
	root := t.TempDir()
	deps := wizardDeps{
		Hostname: func() (string, error) { return "system-host", nil },
		Discover: func(context.Context) (string, string, error) { return "8.8.8.8", "JP", nil },
		Zones: func(context.Context, string) ([]cloudflare.Zone, error) {
			return []cloudflare.Zone{{ID: "zone", Name: "example.com", Status: "active"}}, nil
		},
		Records: func(context.Context, string, string, string) ([]cloudflare.Record, error) { return nil, nil },
		Probe:   func(context.Context, model.Reality) error { return nil },
	}
	// mode, address, hidden Token, zone, subdomain, email, host, country, SNI,
	// protocols, ports, names, quota, expiry, reset schedule, firewall, confirmation.
	answers := []string{"cloudflare", "1.1.1.1", "private-test-token", "1", "node", "owner@example.com", "my-host", "US", "addons.mozilla.org", "", "", "", "", "", "1@0", "auto", "yes"}
	setup, output, err := runWizardTTY(t, answers, deps)
	if err != nil {
		t.Fatal(err, output)
	}
	if setup.Config.Domain != "node.example.com" || setup.Config.Address != "1.1.1.1" || setup.Config.NodeName(setup.Config.Protocols[0]) != "🇺🇸 my-host · VLESS" || setup.Config.Quota != 0 || !setup.Config.ManagedDNS {
		t.Fatal("incorrect wizard candidate")
	}
	if setup.Token != "private-test-token" || setup.TokenPath != "" {
		t.Fatal("wizard did not collect the pasted Token directly")
	}
	if strings.Contains(output, "private-test-token") {
		t.Fatal("Token echoed")
	}
	if strings.Contains(output, "Token文件路径") {
		t.Fatal("wizard still asks for a Token file")
	}
	draft, err := json.Marshal(setup)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(draft, []byte("private-test-token")) {
		t.Fatal("raw Token leaked into setup draft")
	}
	if _, err = os.Stat(filepath.Join(root, "state.db")); !os.IsNotExist(err) {
		t.Fatal("input collection committed state")
	}
	var out bytes.Buffer
	_, err = collectSetup(context.Background(), terminal.New(strings.NewReader(""), &out), deps)
	if err == nil {
		t.Fatal("EOF accepted as approval")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = collectSetup(ctx, terminal.New(strings.NewReader(""), &out), deps)
	if !errors.Is(err, terminal.ErrCanceled) {
		t.Fatal("cancel ignored", err)
	}
}

func TestManagedBootstrapDefaults(t *testing.T) {
	root := t.TempDir()
	var out bytes.Buffer
	args := []string{"--root", root, "init", "--domain", "node.example.com", "--address", "8.8.8.8", "--subscription-mode", "cloudflare", "--managed-dns", "--dns-zone", "zone", "--dry-run"}
	if code := Run(context.Background(), args, strings.NewReader(""), &out, &out); code != 0 {
		t.Fatal(code, out.String())
	}
	b, err := os.ReadFile(filepath.Join(root, "etc/nodekit/bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c model.Config
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if !c.ManagedDNS || c.DisplayMode != "flag-host" || c.Name == "" || c.Reality.ServerName != "addons.mozilla.org" {
		t.Fatal("missing new installation defaults")
	}
	if _, err = os.Stat(filepath.Join(root, "root/nodekit-cloudflare.token")); !os.IsNotExist(err) {
		t.Fatal("dry run saved credentials")
	}
}

func TestSetupRefusesNonTTYPrompt(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"--root", t.TempDir(), "setup"}, strings.NewReader(""), &out, &out); code == 0 {
		t.Fatal("unattended setup accepted")
	}
	if !strings.Contains(out.String(), "终端") {
		t.Fatal("did not explain non-TTY setup", out.String())
	}
}

func TestWizardRejectsAdoptionWithoutExplicitConsent(t *testing.T) {
	deps := wizardDeps{Hostname: func() (string, error) { return "host", nil }, Discover: func(context.Context) (string, string, error) { return "8.8.8.8", "", nil }, Zones: func(context.Context, string) ([]cloudflare.Zone, error) {
		return []cloudflare.Zone{{ID: "z", Name: "example.com", Status: "active"}}, nil
	}, Records: func(context.Context, string, string, string) ([]cloudflare.Record, error) {
		return []cloudflare.Record{{ID: "record", Type: "A", Name: "node.example.com", Content: "1.1.1.1"}}, nil
	}, Probe: func(context.Context, model.Reality) error {
		t.Error("probe after rejected adoption")
		return errors.New("unexpected probe")
	}}
	_, output, err := runWizardTTY(t, []string{"cloudflare", "", "private-test-token", "1", "node", "no"}, deps)
	if !errors.Is(err, terminal.ErrCanceled) {
		t.Fatal("adoption consent ignored", err)
	}
	if !strings.Contains(output, "彻底卸载会删除此记录") {
		t.Fatal("adoption lacks deletion semantics")
	}
}

func TestWizardRejectsInvalidTokenBeforeDNS(t *testing.T) {
	for _, token := range []string{"", "short"} {
		t.Run(fmt.Sprintf("length-%d", len(token)), func(t *testing.T) {
			deps := wizardDeps{
				Discover: func(context.Context) (string, string, error) { return "8.8.8.8", "", nil },
				Zones: func(context.Context, string) ([]cloudflare.Zone, error) {
					t.Error("invalid Token reached the DNS API")
					return nil, errors.New("unexpected DNS request")
				},
			}
			_, _, err := runWizardTTY(t, []string{"cloudflare", "", token}, deps)
			if err == nil || err.Error() != "invalid Token" {
				t.Fatal("invalid Token accepted", err)
			}
		})
	}
}

func TestWizardTokenDoesNotFallBackToVisibleNonTTYInput(t *testing.T) {
	deps := wizardDeps{Discover: func(context.Context) (string, string, error) { return "8.8.8.8", "", nil }}
	var out bytes.Buffer
	s := terminal.New(strings.NewReader("cloudflare\n\nprivate-test-token\n"), &out)
	_, err := collectSetup(context.Background(), s, deps)
	if err == nil || !strings.Contains(err.Error(), "requires a terminal") {
		t.Fatal("wizard did not require a terminal for Token input", err)
	}
	if strings.Contains(out.String(), "private-test-token") {
		t.Fatal("Token echoed")
	}
}

// A real PTY preserves secret-input behavior; only external network calls are
// replaced by wizardDeps. Feed each answer after its prompt, not before echo is
// disabled. Keep prompts on a pipe so the driver cannot confuse input echo with
// subsequent prompts.
func runWizardTTY(t *testing.T, answers []string, deps wizardDeps) (setupInput, string, error) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "wizard-master")
	t.Cleanup(func() { master.Close() })
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { read.Close(); write.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		input setupInput
		err   error
	}
	done := make(chan result, 1)
	go func() {
		input, err := collectSetup(ctx, terminal.New(slave, write), deps)
		write.Close()
		done <- result{input, err}
	}()
	reader := bufio.NewReader(read)
	var output, prompt strings.Builder
	next := 0
	for {
		b, err := reader.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		output.WriteByte(b)
		prompt.WriteByte(b)
		if !strings.HasSuffix(prompt.String(), ": ") {
			continue
		}
		if next >= len(answers) {
			t.Fatal("unexpected wizard prompt", prompt.String())
		}
		if strings.Contains(prompt.String(), "Cloudflare Token（") {
			mode, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || mode.Lflag&(unix.ECHO|unix.ECHONL) != 0 {
				t.Fatal("Token prompt did not disable terminal echo", err)
			}
		}
		if _, err := fmt.Fprintln(master, answers[next]); err != nil {
			t.Fatal(err)
		}
		next++
		prompt.Reset()
	}
	r := <-done
	return r.input, output.String(), r.err
}
