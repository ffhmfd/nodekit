package cli

import (
	"context"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestIPv6RequirementIntentSurvivesConcurrentManifestUpdates(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	if err := os.MkdirAll(p.Etc, 0700); err != nil {
		t.Fatal(err)
	}
	m := hostManifest{RequiredFeatures: []string{"managed-dns-v1"}}
	if err := saveHost(p, m); err != nil {
		t.Fatal(err)
	}
	old, _ := model.New()
	next := savedIPv6Config(t)
	commit, abort, err := beginIPv6Requirement(p, old, next)
	if err != nil {
		t.Fatal(err)
	}
	m, err = loadHost(p)
	if err != nil || !hasIPv6Requirement(m) {
		t.Fatal("pending IPv6 capability not persisted", err)
	}
	oldHelper := filepath.Join(t.TempDir(), "old-helper")
	if err := os.WriteFile(oldHelper, []byte("#!/bin/sh\necho '{\"subscription_modes\":[\"direct\"],\"features\":[\"managed-dns-v1\"]}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkReleaseCompatibility(context.Background(), old, oldHelper, hostFeatures(m)...); err == nil {
		t.Fatal("pending candidate can be handled by an incompatible old helper")
	}
	m.DNSRecords = []cloudflare.ManagedRecord{{ZoneID: "new-zone"}}
	if err := saveHost(p, m); err != nil {
		t.Fatal(err)
	}
	if err := abort(); err != nil {
		t.Fatal(err)
	}
	m, _ = loadHost(p)
	if hasIPv6Requirement(m) || len(m.DNSRecords) != 1 || len(m.RequiredFeatures) != 1 || m.RequiredFeatures[0] != "managed-dns-v1" {
		t.Fatal("abort lost ownership or left spurious requirement")
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	m, _ = loadHost(p)
	if !hasIPv6Requirement(m) || len(m.DNSRecords) != 1 {
		t.Fatal("commit dropped feature/ownership")
	}
}

func TestIPv6RollbackFailureKeepsCapabilityAndFirewallJournal(t *testing.T) {
	p, db, old := ipv6CLIFixture(t)
	if err := saveHost(p, hostManifest{}); err != nil {
		t.Fatal(err)
	}
	next := old.Clone()
	next.IPv6Nodes = savedIPv6Config(t).IPv6Nodes
	_, abortRequirement, err := beginIPv6Requirement(p, old, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(r *store.Record) error {
		r.Operation = &store.Operation{ID: "failed-ipv6-rollback", Phase: "rollback_failed", Old: old, New: next}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rulesUndone := false
	undoRules := func() error { rulesUndone = true; return nil }
	if err := abortConfigChange(p, old, next, undoRules, abortRequirement); err == nil {
		t.Fatal("failed manager rollback reported safe")
	}
	m, err := loadHost(p)
	if err != nil || !hasIPv6Requirement(m) || rulesUndone {
		t.Fatal("pending IPv6 candidate lost capability or firewall journal", err)
	}
	if err := db.Update(func(r *store.Record) error { r.Operation = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := abortConfigChange(p, old, next, undoRules, abortRequirement); err != nil {
		t.Fatal(err)
	}
	m, _ = loadHost(p)
	if hasIPv6Requirement(m) || !rulesUndone {
		t.Fatal("completed rollback cannot restore prior capability state")
	}
}

func TestIPv6RequirementSavedOffAndAbortPreserveOldCapability(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	if err := os.MkdirAll(p.Etc, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveHost(p, hostManifest{}); err != nil {
		t.Fatal(err)
	}
	old := savedIPv6Config(t)
	next := old.Clone()
	next.IPv6Nodes = nil
	commit, abort, err := beginIPv6Requirement(p, old, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := abort(); err != nil {
		t.Fatal(err)
	}
	m, _ := loadHost(p)
	if !hasIPv6Requirement(m) {
		t.Fatal("abort permits incompatible helper for saved off settings")
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	m, _ = loadHost(p)
	if hasIPv6Requirement(m) {
		t.Fatal("explicit complete configuration removal cannot clear requirement")
	}
}

func hasIPv6Requirement(m hostManifest) bool {
	for _, feature := range m.RequiredFeatures {
		if feature == "ipv6-nodes-v1" {
			return true
		}
	}
	return false
}
