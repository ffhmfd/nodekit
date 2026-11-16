package cli

import (
	"bytes"
	"context"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"slices"
	"testing"
)

func TestTrafficMultiplierFreshTransactionAfterRecovery(t *testing.T) {
	p, db, old := ipv6CLIFixture(t)
	if err := saveHost(p, hostManifest{}); err != nil {
		t.Fatal(err)
	}
	// The old process left its intent behind; its callbacks no longer exist.
	if _, _, err := beginConfigRequirements(p, old, trafficConfig(t, old.Clone(), 2)); err != nil {
		t.Fatal(err)
	}
	// Manager recovery has restored the 1x committed configuration and cleared
	// its operation. The host capability must survive until a fresh commit.
	if err := db.Update(func(r *store.Record) error { r.Config = old; r.Operation = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	_, abort, err := beginConfigRequirements(p, old, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := abort(); err != nil {
		t.Fatal(err)
	}
	m, err := loadHost(p)
	if err != nil || !slices.Contains(m.RequiredFeatures, "traffic-multiplier-v1") {
		t.Fatal("aborted fresh transaction lost intent", err)
	}
	commit, _, err := beginConfigRequirements(p, old, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := editWithIPv6Deps(context.Background(), p, []string{"config", "set", "traffic-multiplier", "1"}, &bytes.Buffer{}, ipv6TestDeps()); err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	m, err = loadHost(p)
	if err != nil || slices.Contains(m.RequiredFeatures, "traffic-multiplier-v1") {
		t.Fatal("fresh 1x commit left stale capability", err)
	}
	if err := checkReleaseCompatibility(context.Background(), protocolRecord(t, db).Config, "/does/not/exist", hostFeatures(m)...); err != nil {
		t.Fatal("recovered 1x still blocks legacy helper", err)
	}
}

func TestTrafficMultiplierRequirementTransaction(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	if err := os.MkdirAll(p.Etc, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveHost(p, hostManifest{RequiredFeatures: []string{"managed-dns-v1"}}); err != nil {
		t.Fatal(err)
	}
	old, _ := model.New()
	next := trafficConfig(t, old.Clone(), 2)
	commit, abort, err := beginConfigRequirements(p, old, next)
	if err != nil {
		t.Fatal(err)
	}
	check := func(required bool) {
		t.Helper()
		m, err := loadHost(p)
		if err != nil || slices.Contains(m.RequiredFeatures, "traffic-multiplier-v1") != required || !slices.Contains(m.RequiredFeatures, "managed-dns-v1") {
			t.Fatal("lost capability state", m.RequiredFeatures, err)
		}
	}
	check(true) // intent protects interrupted candidate before config commit
	if err := abort(); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	check(true)
	commit, abort, err = beginConfigRequirements(p, next, old)
	if err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := abort(); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	check(false)
}

func TestTrafficMultiplierFailedRollbackKeepsRequirement(t *testing.T) {
	p, db, old := ipv6CLIFixture(t)
	if err := saveHost(p, hostManifest{}); err != nil {
		t.Fatal(err)
	}
	next := trafficConfig(t, old.Clone(), 2)
	_, abort, err := beginConfigRequirements(p, old, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(r *store.Record) error {
		r.Operation = &store.Operation{ID: "traffic", Phase: "rollback_failed", Old: old, New: next}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rulesUndone := false
	undo := func() error { rulesUndone = true; return nil }
	if err := abortConfigChange(p, old, next, undo, abort); err == nil {
		t.Fatal("pending rollback dropped capability")
	}
	m, err := loadHost(p)
	if err != nil || !slices.Contains(m.RequiredFeatures, "traffic-multiplier-v1") || rulesUndone {
		t.Fatal("pending candidate unprotected", err)
	}
	if err := db.Update(func(r *store.Record) error { r.Operation = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := abortConfigChange(p, old, next, undo, abort); err != nil {
		t.Fatal(err)
	}
	m, err = loadHost(p)
	if err != nil || slices.Contains(m.RequiredFeatures, "traffic-multiplier-v1") || !rulesUndone {
		t.Fatal("recovered rollback not cleaned", err)
	}
}
