package cli

import (
	"context"
	"errors"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestFirewallCompletionPreservesCommittedDNS(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(p.Etc, 0700)
	m := hostManifest{InstallationID: "new-owner", DNSRecords: []cloudflare.ManagedRecord{{ZoneID: "z", Record: cloudflare.Record{ID: "new-record"}}}, PendingFirewall: &firewallOperation{Revision: 7}}
	if err := saveHost(p, m); err != nil {
		t.Fatal(err)
	}
	if err := finishFirewallChange(p, []platform.Binding{{Network: "tcp", Port: 8443}}); err != nil {
		t.Fatal(err)
	}
	got, err := loadHost(p)
	if err != nil || got.InstallationID != "new-owner" || len(got.DNSRecords) != 1 || got.DNSRecords[0].Record.ID != "new-record" || got.PendingFirewall != nil {
		t.Fatal("firewall completion lost DNS ownership", got, err)
	}
}

func TestPurgeDataResumesAfterOwnershipMarkerWasRemoved(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	platform.Claim(p.Data)
	os.MkdirAll(p.Etc, 0700)
	os.WriteFile(filepath.Join(p.Data, "remaining"), []byte("project data"), 0600)
	m := hostManifest{PurgePhase: "files_removed"}
	interrupted := errors.New("interrupted after durable identity")
	if err := removePurgeData(p, &m, func() error {
		if err := saveHost(p, m); err != nil {
			return err
		}
		return interrupted
	}); !errors.Is(err, interrupted) {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(p.Data, ".nodekit-owned"))
	m, err := loadHost(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = removePurgeData(p, &m, func() error { return saveHost(p, m) }); err != nil {
		t.Fatal("cannot resume data removal", err)
	}
	if _, err = os.Stat(p.Data); !os.IsNotExist(err) {
		t.Fatal("data remains")
	}
}

func TestRecoveryLoadsTrustedLegacySnapshotWithBrokenCurrent(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	os.MkdirAll(lifecycleDir(p), 0700)
	c, _ := model.New()
	c.SetDisplayDefaults("saved-host", "JP")
	if err := store.Initialize(filepath.Join(lifecycleDir(p), "state.db"), store.Record{Config: c}); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(p.Data, 0700)
	os.WriteFile(filepath.Join(p.Data, "state.db"), []byte("broken live database"), 0600)
	got, err := recoveryConfig(context.Background(), p, upgradeJournal{Old: "releases/old", New: "releases/broken", Phase: "switched"})
	if err != nil || got.Name != "saved-host" || got.CountryCode != "JP" {
		t.Fatal("legacy recovery depends on live database/current binary", got.Name, err)
	}
}

func TestPurgeRuntimeBeforeServicePermissions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned initialization fixture")
	}
	p := makePaths(t.TempDir(), "")
	if err := platform.Claim(p.Run); err != nil {
		t.Fatal(err)
	}
	m := hostManifest{UID: 999, GID: 999, InitPhase: "prepared"}
	if err := removePurgeRuntime(p, m); err != nil {
		t.Fatal("failed initialization cannot purge", err)
	}
}
