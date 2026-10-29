package manager

import (
	"context"
	"errors"
	"gopkg.in/yaml.v3"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"reflect"
	"testing"
)

type transitionCore struct {
	*fakeCore
	db        *store.Store
	counts    []int
	failAt    int
	noJournal bool
}

func (f *transitionCore) Apply(ctx context.Context, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var config struct {
		Listeners []any `yaml:"listeners"`
	}
	if err = yaml.Unmarshal(b, &config); err != nil {
		return err
	}
	f.counts = append(f.counts, len(config.Listeners))
	r, err := f.db.Load()
	if err != nil {
		return err
	}
	if r.Operation == nil {
		f.noJournal = true
	}
	if f.failAt == len(f.counts) {
		return errors.New("candidate bind failed")
	}
	return f.fakeCore.Apply(ctx, path)
}

func ipv6TransitionConfig(c model.Config) model.Config {
	c = c.Clone()
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
	return c
}

func TestIPv6TransitionDrainsOnlyAfterJournal(t *testing.T) {
	m, core, db := setup(t)
	f := &transitionCore{fakeCore: core, db: db}
	m.core = f
	r, _ := db.Load()
	c := ipv6TransitionConfig(r.Config)
	if err := m.Change(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if f.noJournal || !reflect.DeepEqual(f.counts, []int{0, 6}) {
		t.Fatal("wildcard transition did not drain safely", f.counts, f.noJournal)
	}
	r, _ = db.Load()
	if r.Operation != nil || r.Config.IPv6Nodes == nil || r.Config.Token != c.Token {
		t.Fatal("transition did not commit cleanly")
	}
}

func TestIPv6TransitionFailureDrainsBeforeRestoringLegacy(t *testing.T) {
	m, core, db := setup(t)
	f := &transitionCore{fakeCore: core, db: db, failAt: 2}
	m.core = f
	r, _ := db.Load()
	old := r.Config.Clone()
	if err := m.Change(context.Background(), ipv6TransitionConfig(old)); err == nil {
		t.Fatal("candidate bind failure ignored")
	}
	if !reflect.DeepEqual(f.counts, []int{0, 6, 0, 5}) || f.noJournal {
		t.Fatal("rollback may overlap wildcard sockets", f.counts, f.noJournal)
	}
	r, _ = db.Load()
	if r.Config.IPv6Nodes != nil || r.Operation != nil || r.Config.Token != old.Token || r.Config.Revision != old.Revision {
		t.Fatal("failed candidate replaced old state")
	}
}

func TestIPv6RecoveryDrainsPartiallyAppliedSockets(t *testing.T) {
	m, core, db := setup(t)
	f := &transitionCore{fakeCore: core, db: db}
	m.core = f
	if err := db.Update(func(r *store.Record) error {
		r.Operation = &store.Operation{ID: "interrupted-ipv6", Phase: "prepared", Old: r.Config, New: ipv6TransitionConfig(r.Config)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.counts, []int{0, 5}) || f.noJournal {
		t.Fatal("recovery omitted listener drain", f.counts, f.noJournal)
	}
}

func TestIPv6QuotaOnlyChangeDoesNotDrain(t *testing.T) {
	m, core, db := setup(t)
	f := &transitionCore{fakeCore: core, db: db}
	m.core = f
	if err := db.Update(func(r *store.Record) error { r.Config = ipv6TransitionConfig(r.Config); return nil }); err != nil {
		t.Fatal(err)
	}
	r, _ := db.Load()
	c := r.Config.Clone()
	c.Quota = 500000000000
	if err := m.Change(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.counts, []int{6}) {
		t.Fatal("quota edit unnecessarily drained listeners", f.counts)
	}
}
