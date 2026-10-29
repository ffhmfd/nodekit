package integration

import (
	"context"
	"nodekit/internal/core"
	"nodekit/internal/manager"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestIPv6RealManagerRollbackPreservesLegacyListeners(t *testing.T) {
	bin, dir, old := ipv6CoreFixture(t)
	old.IPv6Nodes = nil
	cp, kp, _ := testCert(t, dir)
	socket := filepath.Join(dir, "s.sock")
	paths := render.Paths{WorkDir: dir, Socket: socket, Certificate: cp, PrivateKey: kp}
	b, err := render.Server(old, paths)
	if err != nil {
		t.Fatal(err)
	}
	startCore(t, bin, dir, b)
	waitPort(t, old.Protocols[0].Port)
	db, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Update(func(r *store.Record) error { r.Config = old; return nil }); err != nil {
		t.Fatal(err)
	}
	control := &core.Client{Socket: socket, Binary: bin, WorkDir: dir}
	mgr, err := manager.New(db, control, nil, paths)
	if err != nil {
		t.Fatal(err)
	}
	next := old.Clone()
	next.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless", "ss"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
	// The valid public fixture is intentionally not assigned to this test host.
	// mihomo accepts its syntax and may log bind errors while returning HTTP 200;
	// exact native endpoint health must reject it and restore the old wildcard.
	if err := mgr.Change(context.Background(), next); err == nil {
		t.Fatal("unassigned IPv6 candidate committed")
	}
	r, err := db.Load()
	if err != nil || r.Operation != nil || r.Config.IPv6Nodes != nil || r.Config.Token != old.Token || r.Config.Revision != old.Revision {
		t.Fatal("failed IPv6 transition did not roll back", err, r.LastError)
	}
	if err := control.Health(context.Background(), old); err != nil {
		t.Fatal("legacy listeners not restored", err)
	}
	waitPort(t, old.Protocols[0].Port)
	if _, err := os.Stat(filepath.Join(dir, "listener-drain.yaml")); !os.IsNotExist(err) {
		t.Fatal("temporary drain file remains", err)
	}
}
