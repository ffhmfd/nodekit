package cli

import (
	"context"
	"nodekit/internal/cloudflare"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Dedicated opt-in records only; never adopts a pre-existing record.
func TestLiveCloudflareOwnershipAndPurge(t *testing.T) {
	zone, suffix, token := os.Getenv("NODEKIT_TEST_ZONE"), os.Getenv("NODEKIT_TEST_DNS_SUFFIX"), os.Getenv("NODEKIT_TEST_TOKEN_FILE")
	origin := os.Getenv("NODEKIT_TEST_ORIGIN")
	if zone == "" || suffix == "" || token == "" || origin == "" {
		t.Skip("explicit disposable DNS zone/suffix/token required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	api, err := cloudflare.New(token)
	if err != nil {
		t.Fatal(err)
	}
	zones, err := api.Zones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, z := range zones {
		if z.ID == zone {
			found = true
		}
	}
	if !found {
		t.Fatal("test zone not visible to Token")
	}
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(p.Etc, 0700)
	os.MkdirAll(filepath.Join(p.Root, "root"), 0700)
	copyPath := filepath.Join(p.Root, "root/nodekit-cloudflare.token")
	b, err := os.ReadFile(token)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(copyPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	id := time.Now().UTC().Format("20060102150405")
	op := cloudflare.Operation{InstallationID: "test-" + id, ZoneID: zone, Desired: cloudflare.Record{Type: "A", Name: "nodekit-test-" + id + "." + suffix, Content: origin, TTL: 1, Proxied: true}}
	save := func() error { return writeJSON(filepath.Join(p.Etc, "intent.json"), op) }
	owned, err := cloudflare.Ensure(ctx, api, &op, save)
	if err != nil {
		t.Fatal(err)
	}
	created := owned
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := cleanupValidationDNS(cleanup, api, created, &op, save); err != nil {
			t.Errorf("test DNS cleanup failed: %s %v", created.Record.Name, err)
		}
	})
	previous := owned.Record
	op = cloudflare.Operation{InstallationID: "test-" + id, ZoneID: zone, Previous: &previous, Desired: cloudflare.Record{Type: "A", Name: previous.Name, Content: "1.1.1.1", TTL: 1, Proxied: false}}
	owned, err = cloudflare.Ensure(ctx, api, &op, save)
	if err != nil {
		t.Fatal(err)
	}
	if err = cloudflare.Rollback(ctx, api, &op, save); err != nil {
		t.Fatal(err)
	}
	owned.Record = previous
	m := hostManifest{DNSRecords: []cloudflare.ManagedRecord{owned}}
	ops := purgeOps{DNS: api, Save: func() error { return saveHost(p, m) }, Credentials: func(context.Context) error { return removePurgeCredentials(p) }, Finish: func(context.Context) error { return nil }}
	if err = runPurge(ctx, &m, ops); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(copyPath); !os.IsNotExist(err) {
		t.Fatal("standard test Token was not removed")
	}
	if _, err = os.Stat(token); err != nil {
		t.Fatal("external Token source was removed")
	}
	if err = cloudflare.DeleteManaged(ctx, api, owned); err != nil {
		t.Fatal("deleted record not idempotent", err)
	}
	t.Log("Dedicated live DNS create, adopt/update, rollback, purge and Token-copy cleanup passed")
}

func cleanupValidationDNS(ctx context.Context, api cloudflare.API, created cloudflare.ManagedRecord, op *cloudflare.Operation, save func() error) error {
	if op.Phase != "rolled_back" {
		if err := cloudflare.Rollback(ctx, api, op, save); err != nil {
			return err
		}
	}
	return cloudflare.DeleteManaged(ctx, api, created)
}

func TestLiveValidationCleanupReconcilesLostUpdate(t *testing.T) {
	before := cloudflare.Record{ID: "r", Name: "node.example.com", Type: "A", Content: "8.8.8.8", TTL: 1, Proxied: true, Comment: "nodekit:test"}
	after := before
	after.Content = "1.1.1.1"
	after.Proxied = false
	api := &memoryDNS{record: &after}
	op := cloudflare.Operation{InstallationID: "test", ZoneID: "z", Previous: &before, Desired: after, Phase: "uncertain"}
	if err := cleanupValidationDNS(context.Background(), api, cloudflare.ManagedRecord{ZoneID: "z", Record: before}, &op, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if api.record != nil {
		t.Fatal("disposable record leaked after failed update")
	}
}
