package cli

import (
	"context"
	"errors"
	"io"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPurgeRetryKeepsCredentialsUntilRemoteCleanup(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	for _, dir := range []string{p.Etc, filepath.Join(p.Root, "root"), p.Data, p.Opt} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	token := filepath.Join(p.Root, "root/nodekit-cloudflare.token")
	os.WriteFile(token, []byte("secret"), 0600)
	os.WriteFile(filepath.Join(p.Etc, "cloudflare.token"), []byte("secret"), 0600)
	r := cloudflare.Record{ID: "r", Type: "A", Name: "node.example.com", Content: "8.8.8.8", TTL: 1, Proxied: true}
	api := &memoryDNS{record: &r, failDelete: true}
	m := hostManifest{DNSRecords: []cloudflare.ManagedRecord{{ZoneID: "z", Record: r}}}
	save := func() error { return saveHost(p, m) }
	var events []string
	failStop := true
	step := func(name string) func(context.Context) error {
		return func(context.Context) error {
			events = append(events, name)
			if _, err := os.Stat(token); err != nil {
				t.Fatal("credential removed before", name)
			}
			return nil
		}
	}
	ops := purgeOps{DNS: api, Save: save, Stop: func(ctx context.Context) error {
		if failStop {
			failStop = false
			return errors.New("stop interrupted")
		}
		return step("stop")(ctx)
	}, Firewall: step("firewall"), Files: step("files"), Data: step("data"), Account: step("account"), Credentials: func(context.Context) error { events = append(events, "credentials"); return removePurgeCredentials(p) }, Finish: func(context.Context) error {
		events = append(events, "finish")
		if _, err := os.Stat(token); !os.IsNotExist(err) {
			t.Fatal("token remains")
		}
		return nil
	}}
	if err := runPurge(context.Background(), &m, ops); err == nil || len(events) != 0 {
		t.Fatal("DNS failure did not stop local cleanup")
	}
	if _, err := os.Stat(token); err != nil {
		t.Fatal("lost retry credentials")
	}
	api.failDelete = false
	if err := runPurge(context.Background(), &m, ops); err == nil {
		t.Fatal("expected stop interruption")
	}
	var err error
	m, err = loadHost(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = runPurge(context.Background(), &m, ops); err != nil {
		t.Fatal(err)
	}
	if api.deletes != 1 || !reflect.DeepEqual(events, []string{"stop", "firewall", "files", "data", "account", "credentials", "finish"}) {
		t.Fatal("retry ordering wrong", events, api.deletes)
	}
}

func TestPurgeCredentialRemovalDoesNotFollowLinks(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(filepath.Join(p.Root, "root"), 0700)
	os.MkdirAll(p.Etc, 0700)
	external := filepath.Join(t.TempDir(), "custom-token")
	os.WriteFile(external, []byte("preserve"), 0600)
	if err := os.Symlink(external, filepath.Join(p.Root, "root/nodekit-cloudflare.token")); err != nil {
		t.Fatal(err)
	}
	if err := removePurgeCredentials(p); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(external)
	if err != nil || string(data) != "preserve" {
		t.Fatal("external Token source deleted")
	}
}

func TestLegacyDNSDiscoveryMustMatchNode(t *testing.T) {
	c, _ := model.New()
	c.Address = "8.8.8.8"
	c.SubscriptionMode = "cloudflare"
	c.SubscriptionPort = 8443
	r := cloudflare.Record{ID: "r", Type: "A", Name: c.Domain, Content: c.Address, Proxied: true, TTL: 1}
	api := &memoryDNS{record: &r}
	rows, err := discoverLegacyDNS(context.Background(), api, "z", c)
	if err != nil || len(rows) != 1 || rows[0].Record.ID != "r" {
		t.Fatal(err)
	}
	r.Content = "1.1.1.1"
	if _, err = discoverLegacyDNS(context.Background(), api, "z", c); err == nil {
		t.Fatal("adopted wrong origin")
	}
	api.record = nil
	if _, err = discoverLegacyDNS(context.Background(), api, "z", c); err == nil {
		t.Fatal("untracked missing DNS treated as verified cleanup")
	}
}

func TestRetainedStateRecordsRequiredFeatures(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(p.Etc, 0700)
	c, _ := model.New()
	c.SetDisplayDefaults("host", "JP")
	c.ManagedDNS = true
	m := hostManifest{}
	if err := saveRetainedRequirements(p, &m, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(p.Etc, "required-features"))
	if err != nil {
		t.Fatal(err)
	}
	for _, feature := range []string{"node-names-v1", "managed-dns-v1", "purge-v1"} {
		if !strings.Contains(string(data), feature+"\n") {
			t.Fatal("retained installation lost capability requirement", feature)
		}
	}
}

func TestPurgeRefusesTrackedDNSWithoutCredentials(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	if err := os.MkdirAll(p.Etc, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(p.Etc, "runtime.json"), runtimeConfig{Firewall: "manual"}); err != nil {
		t.Fatal(err)
	}
	m := hostManifest{DNSRecords: []cloudflare.ManagedRecord{{ZoneID: "z", Record: cloudflare.Record{ID: "r"}}}}
	if _, err := preparePurgeDNS(context.Background(), p, &m, io.Discard); err == nil {
		t.Fatal("missing DNS credentials did not block purge")
	}
}

func TestPurgeCanCleanFailedInitBeforeRuntimeExists(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(p.Etc, 0700)
	m := hostManifest{}
	if _, err := preparePurgeDNS(context.Background(), p, &m, io.Discard); err != nil {
		t.Fatal("unconfigured host cannot be cleaned", err)
	}
	os.MkdirAll(p.Data, 0700)
	os.WriteFile(filepath.Join(p.Data, "state.db"), []byte("existing state"), 0600)
	if _, err := preparePurgeDNS(context.Background(), p, &m, io.Discard); err == nil {
		t.Fatal("ignored missing runtime for an initialized host")
	}
}

func TestPurgeRuntimeDirectoryAfterReboot(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	if err := os.MkdirAll(p.Run, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.Run, 0700); err != nil {
		t.Fatal(err)
	}
	// tmpfiles recreates /run/nodekit without a persistent ownership marker.
	os.WriteFile(filepath.Join(p.Run, "core.sock"), nil, 0600)
	m := hostManifest{UID: os.Getuid() + 1, GID: os.Getgid()}
	if err := removePurgeRuntime(p, m); err == nil {
		t.Fatal("removed directory with a different owner")
	}
	m.UID = os.Getuid()
	if err := removePurgeRuntime(p, m); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.Run); !os.IsNotExist(err) {
		t.Fatal("runtime directory remains")
	}
}

func TestPurgeCancellationPersistsCompletedDNSDeletion(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(p.Etc, 0700)
	r := cloudflare.Record{ID: "r", Type: "A", Name: "node.example.com", Content: "8.8.8.8", TTL: 1}
	api := &memoryDNS{record: &r}
	m := hostManifest{DNSRecords: []cloudflare.ManagedRecord{{ZoneID: "z", Record: r}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := false
	ops := purgeOps{DNS: api, Save: func() error {
		err := saveHost(p, m)
		if m.PurgePhase == "prepared" && len(m.DNSRecords) == 0 {
			cancel()
		}
		return err
	}, Stop: func(context.Context) error { stopped = true; return nil }, Finish: func(context.Context) error { return nil }}
	if err := runPurge(ctx, &m, ops); !errors.Is(err, context.Canceled) || stopped {
		t.Fatal("unsafe cancellation", err)
	}
	m, err := loadHost(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = runPurge(context.Background(), &m, ops); err != nil || !stopped || api.deletes != 1 {
		t.Fatal("canceled purge did not resume", err)
	}
}
