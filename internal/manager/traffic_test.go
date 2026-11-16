package manager

import (
	"context"
	"nodekit/internal/meter"
	"nodekit/internal/store"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestTrafficMultiplierSwitchPersistsRawUsage(t *testing.T) {
	m, f, db := setup(t)
	ctx := context.Background()
	if err := m.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	initial, err := db.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, multiplier := range []int{2, 1, 2} {
		r, err := db.Load()
		if err != nil {
			t.Fatal(err)
		}
		r.Config.TrafficMultiplier = multiplier
		if err := m.Change(ctx, r.Config); err != nil {
			t.Fatal(err)
		}
		r, err = db.Load()
		if err != nil || !reflect.DeepEqual(r.Meter, initial.Meter) {
			t.Fatal("switch mutated raw usage", err)
		}
	}
	// Reopen the actual persisted DB, then create a new manager over it.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(filepath.Join(m.paths.WorkDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m, err = New(db, f, nil, m.paths)
	if err != nil {
		t.Fatal(err)
	}
	r, err := db.Load()
	if err != nil || r.Config.EffectiveTrafficMultiplier() != 2 || !reflect.DeepEqual(r.Meter, initial.Meter) {
		t.Fatal("restart lost config/counters", err)
	}
	if err := m.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	f.sample.Upload += 10
	f.sample.Download += 100
	f.sample.At = f.sample.At.Add(time.Second)
	if err := m.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	r, err = db.Load()
	if err != nil {
		t.Fatal(err)
	}
	u, d := r.Config.TrafficUsage(r.Meter.Upload, r.Meter.Download)
	if r.Meter.Upload != 10 || r.Meter.Download != 100 || u != 20 || d != 200 || !r.Meter.Next.Equal(initial.Meter.Next) {
		t.Fatal("reset changed multiplier or raw baseline", r.Meter)
	}
}

func TestTrafficMultiplierMonthlyReset(t *testing.T) {
	m, f, db := setup(t)
	ctx := context.Background()
	boundary := time.Date(2026, 12, 1, 0, 0, 0, 0, time.FixedZone("CST", 8*3600))
	f.sample = meter.Sample{Epoch: "one", StartedAt: boundary.Add(-time.Hour), At: boundary.Add(-time.Second), Upload: 10, Download: 100}
	if err := db.Update(func(r *store.Record) error { r.Config.TrafficMultiplier = 2; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	f.sample.At = boundary.Add(time.Second)
	f.sample.Upload, f.sample.Download = 13, 107
	if err := m.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := db.Load()
	if err != nil {
		t.Fatal(err)
	}
	u, d := r.Config.TrafficUsage(r.Meter.Upload, r.Meter.Download)
	if r.Meter.Upload != 3 || r.Meter.Download != 7 || u != 6 || d != 14 || !r.Meter.PeriodStart.Equal(boundary) {
		t.Fatal("monthly raw accounting changed", r.Meter)
	}
}
