package manager

import (
	"context"
	"errors"
	"nodekit/internal/meter"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeCore struct {
	sample                                       meter.Sample
	failSample, failCheck, failApply, failHealth bool
	applied                                      []string
}

func TestConcurrentResetPreservesQuotaSchedule(t *testing.T) {
	m, _, db := setup(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := m.Reset(context.Background()); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	r, e := db.Load()
	if e != nil || r.Meter.Upload != 0 || r.Meter.Download != 0 || r.Config.ResetDay != 1 || r.Config.ResetHour != 0 {
		t.Fatal("concurrent reset corrupted state", e)
	}
}

func (f *fakeCore) Snapshot(context.Context) (meter.Sample, error) {
	if f.failSample {
		return meter.Sample{}, errors.New("offline")
	}
	return f.sample, nil
}
func (f *fakeCore) Check(context.Context, []byte) error {
	if f.failCheck {
		return errors.New("bad config")
	}
	return nil
}
func (f *fakeCore) Apply(_ context.Context, p string) error {
	f.applied = append(f.applied, p)
	if f.failApply {
		return errors.New("apply failed")
	}
	return nil
}
func (f *fakeCore) Health(context.Context, model.Config) error {
	if f.failHealth {
		f.failHealth = false
		return errors.New("listener missing")
	}
	return nil
}
func setup(t *testing.T) (*Manager, *fakeCore, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	db, e := store.Open(filepath.Join(dir, "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	c, _ := model.New()
	if e = db.Update(func(r *store.Record) error { r.Config = c; return nil }); e != nil {
		t.Fatal(e)
	}
	f := &fakeCore{sample: meter.Sample{Epoch: "one", StartedAt: time.Now(), At: time.Now(), Upload: 100, Download: 200}}
	m, e := New(db, f, nil, render.Paths{WorkDir: dir, Socket: filepath.Join(dir, "core.sock"), Certificate: filepath.Join(dir, "cert.pem"), PrivateKey: filepath.Join(dir, "key.pem")})
	if e != nil {
		t.Fatal(e)
	}
	return m, f, db
}
func TestFlushResetAndOffline(t *testing.T) {
	m, f, db := setup(t)
	ctx := context.Background()
	if e := m.Flush(ctx); e != nil {
		t.Fatal(e)
	}
	r, _ := db.Load()
	if r.Meter.Upload != 100 {
		t.Fatal(r.Meter)
	}
	f.failSample = true
	if e := m.Reset(ctx); e == nil {
		t.Fatal("reset while offline")
	}
	r, _ = db.Load()
	if r.Meter.Upload != 100 {
		t.Fatal("offline erased usage")
	}
	f.failSample = false
	next := r.Meter.Next
	if e := m.Reset(ctx); e != nil {
		t.Fatal(e)
	}
	r, _ = db.Load()
	if r.Meter.Upload != 0 || !r.Meter.Next.Equal(next) {
		t.Fatal("reset schedule")
	}
}
func TestChangeRollbackAndRecovery(t *testing.T) {
	for _, phase := range []string{"check", "apply", "health", "success"} {
		t.Run(phase, func(t *testing.T) {
			m, f, db := setup(t)
			r, _ := db.Load()
			old := r.Config
			candidate := old
			candidate.Name = "updated"
			switch phase {
			case "check":
				f.failCheck = true
			case "apply":
				f.failApply = true
			case "health":
				f.failHealth = true
			}
			e := m.Change(context.Background(), candidate)
			r, _ = db.Load()
			if phase == "success" {
				if e != nil || r.Config.Name != "updated" || r.Config.Revision != old.Revision+1 {
					t.Fatal("commit", e)
				}
			} else {
				if e == nil || r.Config.Name != old.Name {
					t.Fatal("published failed revision", e)
				}
			}
		})
	}
	m, f, db := setup(t)
	r, _ := db.Load()
	candidate := r.Config
	candidate.Name = "uncommitted"
	if e := db.Update(func(r *store.Record) error {
		r.Operation = &store.Operation{ID: "crash", Phase: "applied", Old: r.Config, New: candidate}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := m.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	r, _ = db.Load()
	if r.Config.Name == "uncommitted" || r.Operation != nil || len(f.applied) == 0 {
		t.Fatal("bad recovery")
	}
	if _, e := os.Stat(filepath.Join(m.paths.WorkDir, "active.yaml")); e != nil {
		t.Fatal(e)
	}
}
