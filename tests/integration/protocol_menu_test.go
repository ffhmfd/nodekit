package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"nodekit/internal/cli"
	"nodekit/internal/core"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Exercise the user-facing menu, real manager commits/reloads, kernel listeners,
// and HTTPS subscriptions together. Direct protocol commands cannot stand in
// for menu dispatch here: a wrong action/selection must fail these assertions.
func TestProtocolMenuRealCoreLifecycle(t *testing.T) {
	bin := os.Getenv("NODEKIT_CORE_BIN")
	if bin == "" {
		t.Skip("set NODEKIT_CORE_BIN")
	}
	root, err := os.MkdirTemp("", "nk-menu-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	cfg, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Reality.Target = localRealityTarget(t)
	used := map[int]bool{}
	nextPort := func() int {
		for {
			port := freePort(t)
			if !used[port] {
				used[port] = true
				return port
			}
		}
	}
	for i := range cfg.Protocols {
		cfg.Protocols[i].Port = nextPort()
	}
	cfg.SubscriptionPort = nextPort()
	cp, kp, trust := testCert(t, root)
	input := filepath.Join(root, "input.json")
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input, b, 0600); err != nil {
		t.Fatal(err)
	}
	prefix := []string{"--root", root, "--core-bin", bin}
	args := func(command ...string) []string { return append(append([]string{}, prefix...), command...) }
	var out, stderr bytes.Buffer
	if code := cli.Run(context.Background(), args("init", "--config", input, "--certificate", cp, "--key", kp, "--no-service"), strings.NewReader(""), &out, &stderr); code != 0 {
		t.Fatal("isolated initialization failed", stderr.String())
	}
	data := filepath.Join(root, "var/lib/nodekit")
	activePath := filepath.Join(data, "active.yaml")
	readActive := func(t *testing.T) []byte {
		t.Helper()
		b, err := os.ReadFile(activePath)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	startCore(t, bin, data, readActive(t))
	waitPort(t, cfg.Protocols[0].Port)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- cli.Run(ctx, args("serve"), strings.NewReader(""), io.Discard, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("manager did not stop")
		}
	})
	waitPort(t, cfg.SubscriptionPort)
	db, err := store.Open(filepath.Join(data, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	initial, err := db.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := initial.Config.Clone()
	control := &core.Client{Socket: filepath.Join(root, "run/nodekit/core.sock"), Binary: bin, WorkDir: data}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trust) {
		t.Fatal("invalid test trust root")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: cfg.Domain}}
	t.Cleanup(tr.CloseIdleConnections)
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	links := func(t *testing.T) string {
		t.Helper()
		var out, stderr bytes.Buffer
		if code := cli.Run(context.Background(), args("subscription"), strings.NewReader(""), &out, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatal("subscription query failed", stderr.String())
		}
		return out.String()
	}
	originalLinks := links(t)
	checkState := func(t *testing.T) {
		t.Helper()
		record, err := db.Load()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(record.Config, want) || record.Operation != nil {
			t.Fatal("persisted configuration differs: token, credentials, unrelated settings or revision changed")
		}
		if links(t) != originalLinks {
			t.Fatal("protocol operation changed subscription URLs")
		}
		if err := control.Health(context.Background(), want); err != nil {
			t.Fatal("real core listener health", err)
		}
		for _, protocol := range want.Protocols {
			assertProtocolMenuBindings(t, protocol, protocol.Enabled)
		}
		for _, file := range []string{"config.yaml", "proxies.yaml"} {
			// Always request the ORIGINAL subscription port/token, even after edits.
			url := fmt.Sprintf("https://127.0.0.1:%d/s/%s/%s", cfg.SubscriptionPort, cfg.Token, file)
			res, err := hc.Get(url)
			if err != nil {
				t.Fatal("subscription fetch failed", err)
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil || res.StatusCode != http.StatusOK {
				t.Fatal("subscription response", file, res.StatusCode, err)
			}
			var document struct {
				Proxies []struct {
					Type, Server, UUID, Password string
					Port                         int
				} `yaml:"proxies"`
				Groups []any `yaml:"proxy-groups"`
			}
			if err = yaml.Unmarshal(body, &document); err != nil {
				t.Fatal(err)
			}
			if (len(document.Groups) > 0) != (file == "config.yaml") {
				t.Fatal("full/provider subscription shape changed", file)
			}
			seen := map[string]bool{}
			for _, node := range document.Proxies {
				found := false
				for _, protocol := range want.Protocols {
					if node.Type != protocol.Type || !protocol.Enabled {
						continue
					}
					found = true
					if seen[node.Type] || node.Port != protocol.Port || node.Server != cfg.Domain {
						t.Fatal("subscription has duplicate node or wrong endpoint", file, node.Type)
					}
					if (node.Type == "vless" || node.Type == "tuic") && node.UUID != protocol.UUID {
						t.Fatal("subscription UUID changed", file, node.Type)
					}
					if node.Type != "vless" && node.Password != protocol.Password {
						t.Fatal("subscription password changed", file, node.Type)
					}
					seen[node.Type] = true
				}
				if !found {
					t.Fatal("disabled or unexpected protocol in subscription", file, node.Type)
				}
			}
			for _, protocol := range want.Protocols {
				if seen[protocol.Type] != protocol.Enabled {
					t.Fatal("enabled protocol missing from subscription", file, protocol.Type)
				}
			}
		}
	}
	runMenu := func(t *testing.T, index int, action string, rejected bool) {
		t.Helper()
		var out, stderr bytes.Buffer
		input := fmt.Sprintf("8\n%d\n%s\n0\n0\n", index+1, action)
		if code := cli.Run(context.Background(), args(), strings.NewReader(input), &out, &stderr); code != 0 {
			t.Fatal("menu exit", code, stderr.String())
		}
		if rejected {
			if !strings.Contains(stderr.String(), "port occupied") || strings.Contains(out.String(), "刷新订阅") {
				t.Fatal("occupied port not clearly refused", stderr.String(), out.String())
			}
		} else if stderr.Len() != 0 || !strings.Contains(out.String(), "刷新订阅") {
			t.Fatal("menu operation failed", stderr.String(), out.String())
		}
	}
	checkState(t)
	for i, protocol := range cfg.Protocols {
		if !t.Run(protocol.Type, func(t *testing.T) {
			old := want.Protocols[i]
			port := nextPort()
			runMenu(t, i, fmt.Sprintf("3\n%d", port), false)
			want.Protocols[i].Port = port
			want.Revision++
			checkState(t)
			assertProtocolMenuBindings(t, old, false)
			t.Log("menu port change: new listener and both HTTPS subscriptions updated; old listener released")

			runMenu(t, i, "2", false)
			want.Protocols[i].Enabled = false
			want.Revision++
			checkState(t)
			t.Log("menu disable: listener released and protocol absent from both subscriptions")
			runMenu(t, i, "1", false)
			want.Protocols[i].Enabled = true
			want.Revision++
			checkState(t)
			t.Log("menu enable: listener and both subscription nodes restored")

			blockedPort := nextPort()
			blocked, err := bindProtocolMenuPort(protocolMenuNetworks(protocol.Type)[0], blockedPort)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Close()
			before := readActive(t)
			runMenu(t, i, fmt.Sprintf("3\n%d", blockedPort), true)
			checkState(t)
			if !bytes.Equal(before, readActive(t)) {
				t.Fatal("occupied-port refusal changed active core configuration")
			}
			t.Log("menu occupied-port refusal: config/revision, active YAML, listener, URLs and all credentials preserved")
		}) {
			return
		}
	}
}

func protocolMenuNetworks(typ string) []string {
	switch typ {
	case "ss":
		return []string{"tcp4", "udp4"}
	case "tuic", "hysteria2":
		return []string{"udp4"}
	default:
		return []string{"tcp4"}
	}
}

func bindProtocolMenuPort(network string, port int) (io.Closer, error) {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	if network == "udp4" {
		return net.ListenPacket(network, address)
	}
	return net.Listen(network, address)
}

func assertProtocolMenuBindings(t *testing.T, protocol model.Protocol, present bool) {
	t.Helper()
	for _, network := range protocolMenuNetworks(protocol.Type) {
		listener, err := bindProtocolMenuPort(network, protocol.Port)
		if err == nil {
			listener.Close()
		}
		if (present && !errors.Is(err, syscall.EADDRINUSE)) || (!present && err != nil) {
			t.Fatalf("%s %s/%d: want bound=%t, bind error=%v", protocol.Type, network, protocol.Port, present, err)
		}
	}
}
