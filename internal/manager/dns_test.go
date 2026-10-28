package manager

import (
	"context"
	"nodekit/internal/store"
	"testing"
)

func TestManagedDNSChangesRequireCoordinator(t *testing.T) {
	for _, field := range []string{"domain", "address", "mode", "disable"} {
		t.Run(field, func(t *testing.T) {
			m, core, db := setup(t)
			if err := db.Update(func(r *store.Record) error { r.Config.ManagedDNS = true; r.Config.Address = "8.8.8.8"; return nil }); err != nil {
				t.Fatal(err)
			}
			r, _ := db.Load()
			next := r.Config.Clone()
			switch field {
			case "domain":
				next.Domain = "new.example.com"
			case "address":
				next.Address = "1.1.1.1"
			case "mode":
				next.SetSubscriptionMode("cloudflare")
			case "disable":
				next.ManagedDNS = false
			}
			if err := m.Change(context.Background(), next); err == nil {
				t.Fatal("ordinary config API changed managed DNS")
			}
			if len(core.applied) != 0 {
				t.Fatal("refused DNS edit reloaded core")
			}
			if err := m.ChangeManaged(context.Background(), next); err != nil {
				t.Fatal("coordinator edit rejected", err)
			}
		})
	}
	m, _, db := setup(t)
	r, _ := db.Load()
	r.Config.ManagedDNS = true
	if err := m.Change(context.Background(), r.Config); err == nil {
		t.Fatal("ordinary API adopted DNS ownership")
	}
	if err := m.ChangeManaged(context.Background(), r.Config); err != nil {
		t.Fatal(err)
	}
	r, _ = db.Load()
	r.Config.Name = "new display"
	if err := m.Change(context.Background(), r.Config); err != nil {
		t.Fatal("unrelated setting blocked", err)
	}
}
