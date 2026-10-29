package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"nodekit/internal/httpapi"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/store"
	"nodekit/internal/terminal"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func ipv6CLIFixture(t *testing.T) (paths, *store.Store, model.Config) {
	t.Helper()
	root, err := os.MkdirTemp("", "nk6-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	p := makePaths(root, "")
	for _, dir := range []string{p.Etc, p.Run} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := p.db()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.Address = "8.8.8.8"
	if err := db.Update(func(r *store.Record) error { r.Config = c; r.Meter.Upload = 123; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(p.Etc, "runtime.json"), runtimeConfig{Firewall: "manual"}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(p.Run, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: httpapi.Admin(editBackend{certBackend{db}})}
	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })
	return p, db, c
}

func ipv6TestDeps() ipv6Deps {
	return ipv6Deps{
		Addresses: func() ([]localAddress, error) {
			return []localAddress{
				{Interface: "eth0", Address: netip.MustParseAddr("10.0.0.4"), Up: true},
				{Interface: "lo", Address: netip.MustParseAddr("127.0.0.1"), Up: true},
				{Interface: "eth0", Address: netip.MustParseAddr("2001:4860:4860::8888"), Up: true},
				{Interface: "down0", Address: netip.MustParseAddr("2606:4700:4700::1111"), Up: false},
				{Interface: "eth0", Address: netip.MustParseAddr("fe80::1"), Up: true},
			}, nil
		},
		CheckPorts: func(model.Config, []platform.Binding) error { return nil },
	}
}

func TestIPv6ConfigureSelectsProtocolsIndependentlyAndUsesNATBind(t *testing.T) {
	p, db, old := ipv6CLIFixture(t)
	old.Protocols[1].Enabled = false
	old.Protocols[3].Enabled = false
	if err := db.Update(func(r *store.Record) error { r.Config = old; return nil }); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"ipv6", "configure", "--address", "2001:4860:4860:0:0:0:0:8888", "--protocols", "hy2,ss2022"}
	if err := editWithIPv6Deps(context.Background(), p, args, &out, ipv6TestDeps()); err != nil {
		t.Fatal(err)
	}
	r, _ := db.Load()
	if !r.Config.HasIPv6Nodes() || !r.Config.IPv6ProtocolEnabled("ss") || !r.Config.IPv6ProtocolEnabled("hysteria2") || r.Config.IPv6ProtocolEnabled("vless") {
		t.Fatal("IPv6 selection copied the original flags")
	}
	if r.Config.IPv6Nodes.Address != "2001:4860:4860::8888" || !reflect.DeepEqual(r.Config.IPv6Nodes.IPv4ListenAddresses, []string{"10.0.0.4", "127.0.0.1"}) {
		t.Fatal("NAT bind addresses/canonical IPv6 not saved", r.Config.IPv6Nodes)
	}
	if !reflect.DeepEqual(r.Config.Protocols, old.Protocols) || r.Config.Token != old.Token || r.Config.IPv6 || r.Config.Address != old.Address || r.Config.Domain != old.Domain || r.Config.SubscriptionPort != old.SubscriptionPort || r.Meter.Upload != 123 {
		t.Fatal("IPv6 configure changed original node settings/usage")
	}
	if strings.Contains(out.String(), old.Token) {
		t.Fatal("status leaked subscription token")
	}
}

func TestIPv6ConfigureRejectsUnassignedDownOrEmptySelection(t *testing.T) {
	for _, tc := range []struct{ address, protocols string }{
		{"2001:4860:4860::8844", "vless"},
		{"2606:4700:4700::1111", "vless"},
		{"2001:db8::1", "vless"},
		{"::ffff:8.8.8.8", "vless"},
		{"2001:4860:4860::8888", ""},
		{"2001:4860:4860::8888", "ss,ss2022"},
		{"2001:4860:4860::8888", "bogus"},
	} {
		t.Run(tc.address+"/"+tc.protocols, func(t *testing.T) {
			p, db, old := ipv6CLIFixture(t)
			var out bytes.Buffer
			args := []string{"ipv6", "configure", "--address", tc.address, "--protocols", tc.protocols}
			if err := editWithIPv6Deps(context.Background(), p, args, &out, ipv6TestDeps()); err == nil {
				t.Fatal("invalid input committed")
			}
			r, _ := db.Load()
			if !reflect.DeepEqual(r.Config, old) || r.Meter.Upload != 123 {
				t.Fatal("failed configure changed state")
			}
		})
	}
}

func TestIPv6DisableRetainsSelectionWithoutRequiringOldIPv6Assignment(t *testing.T) {
	p, db, c := ipv6CLIFixture(t)
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless"}, IPv4ListenAddresses: []string{"10.0.0.4", "127.0.0.1"}}
	if err := db.Update(func(r *store.Record) error { r.Config = c; return nil }); err != nil {
		t.Fatal(err)
	}
	deps := ipv6TestDeps()
	deps.Addresses = func() ([]localAddress, error) {
		return []localAddress{{Address: netip.MustParseAddr("10.0.0.4"), Up: true}, {Address: netip.MustParseAddr("127.0.0.1"), Up: true}}, nil
	}
	var out bytes.Buffer
	if err := editWithIPv6Deps(context.Background(), p, []string{"ipv6", "disable"}, &out, deps); err != nil {
		t.Fatal(err)
	}
	r, _ := db.Load()
	if r.Config.IPv6Nodes == nil || r.Config.HasIPv6Nodes() || r.Config.IPv6Nodes.Address != c.IPv6Nodes.Address || !reflect.DeepEqual(r.Config.IPv6Nodes.Protocols, []string{"vless"}) || !reflect.DeepEqual(r.Config.Protocols, c.Protocols) || r.Meter.Upload != 123 {
		t.Fatal("disable removed saved or original settings")
	}
	if err := editWithIPv6Deps(context.Background(), p, []string{"ipv6", "enable"}, &out, ipv6TestDeps()); err != nil {
		t.Fatal(err)
	}
	r, _ = db.Load()
	if !r.Config.HasIPv6Nodes() || !r.Config.IPv6ProtocolEnabled("vless") {
		t.Fatal("saved selection not re-enabled")
	}
}

func TestIPv6MenuRequiresExplicitSelectionAndConfirmation(t *testing.T) {
	for _, input := range []string{"2\n1\n\n", "2\n1\nvless\n", "2\n1\nvless\nno\n0\n"} {
		p, db, old := ipv6CLIFixture(t)
		var out bytes.Buffer
		s := terminal.New(strings.NewReader(input), &out)
		_ = ipv6Menu(context.Background(), p, s, &out, ipv6TestDeps())
		r, _ := db.Load()
		if !reflect.DeepEqual(r.Config, old) {
			t.Fatal("unconfirmed or implicit selection committed")
		}
	}
	p, db, _ := ipv6CLIFixture(t)
	var out bytes.Buffer
	s := terminal.New(strings.NewReader("2\n1\nhy2,vless\nyes\n0\n"), &out)
	if err := ipv6Menu(context.Background(), p, s, &out, ipv6TestDeps()); err != nil {
		t.Fatal(err, out.String())
	}
	r, _ := db.Load()
	if !r.Config.IPv6ProtocolEnabled("vless") || !r.Config.IPv6ProtocolEnabled("hysteria2") || r.Config.IPv6ProtocolEnabled("tuic") {
		t.Fatal("menu ignored explicit protocol selection")
	}
}

func TestIPv6ImportCannotBypassAssignedAddressCheck(t *testing.T) {
	p, db, old := ipv6CLIFixture(t)
	c := old.Clone()
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8844", Protocols: []string{"vless"}, IPv4ListenAddresses: []string{"10.0.0.4"}}
	b, _ := json.Marshal(c)
	file := filepath.Join(p.Etc, "import.json")
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := editWithIPv6Deps(context.Background(), p, []string{"config", "apply", file}, &out, ipv6TestDeps()); err == nil {
		t.Fatal("unassigned IPv6 imported")
	}
	r, _ := db.Load()
	if !reflect.DeepEqual(r.Config, old) {
		t.Fatal("invalid import changed state")
	}
}

func TestIPv6StatusCommandWithoutConfigurationWrites(t *testing.T) {
	p, db, old := ipv6CLIFixture(t)
	var out bytes.Buffer
	code := Run(context.Background(), []string{"--root", p.Root, "ipv6", "status"}, strings.NewReader(""), &out, &out)
	if code != 0 || !strings.Contains(out.String(), "IPv6") || !strings.Contains(out.String(), "未配置") {
		t.Fatal("missing IPv6 status command", code, out.String())
	}
	r, _ := db.Load()
	if r.Config.Token != old.Token || r.Config.IPv6Nodes != nil || r.Meter.Upload != 123 {
		t.Fatal("read-only IPv6 status changed installation")
	}
}

func TestIPv6MenuEntryCanShowStatusAndReturn(t *testing.T) {
	p, _, _ := ipv6CLIFixture(t)
	var out, errOut bytes.Buffer
	menu(context.Background(), p, strings.NewReader("24\n1\n0\n0\n"), &out, &errOut)
	if errOut.Len() != 0 || !strings.Contains(out.String(), "24 IPv6节点管理") || !strings.Contains(out.String(), "未配置") {
		t.Fatal("IPv6 menu entry unavailable", errOut.String(), out.String())
	}
}

func savedIPv6Config(t *testing.T) model.Config {
	t.Helper()
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.Address = "8.8.8.8"
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	fields["ipv6_nodes"] = json.RawMessage(`{"enabled":false,"address":"2001:4860:4860::8888","protocols":["vless"],"ipv4_listen_addresses":["127.0.0.1"]}`)
	b, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIPv6CapabilitiesAdvertised(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"capabilities"}, strings.NewReader(""), &out, &out); code != 0 {
		t.Fatal("capabilities failed", code)
	}
	var result capabilities
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, feature := range result.Features {
		if feature == "ipv6-nodes-v1" {
			return
		}
	}
	t.Fatal("IPv6 nodes capability not advertised")
}

func TestIPv6SavedDisabledSettingsRejectOldHelper(t *testing.T) {
	c := savedIPv6Config(t)
	binary := filepath.Join(t.TempDir(), "old-nodekit")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho '{\"subscription_modes\":[\"direct\",\"cloudflare\"],\"features\":[]}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkReleaseCompatibility(context.Background(), c, binary); err == nil {
		t.Fatal("old helper can discard saved IPv6 settings")
	}
}

func TestIPv6RetainedRequirementsPersistEvenWhenDisabled(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	if err := os.MkdirAll(p.Etc, 0700); err != nil {
		t.Fatal(err)
	}
	m := hostManifest{}
	if err := saveRetainedRequirements(p, &m, savedIPv6Config(t)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(p.Etc, "required-features"))
	if err != nil || !strings.Contains(string(b), "ipv6-nodes-v1\n") {
		t.Fatal("retained install can lose IPv6 configuration", err)
	}
}
