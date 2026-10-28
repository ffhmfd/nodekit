package manager

import (
	"context"
	"nodekit/internal/store"
	"testing"
)

func TestSamplingPreservesDegradedOperation(t *testing.T) {
	m, _, db := setup(t)
	if e := db.Update(func(r *store.Record) error {
		r.LastError = "rollback failed"
		r.Operation = &store.Operation{ID: "broken", Phase: "rollback_failed", Old: r.Config, New: r.Config}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := m.Flush(context.Background()); e != nil {
		t.Fatal(e)
	}
	r, _ := db.Load()
	if r.LastError != "rollback failed" || r.Operation == nil {
		t.Fatal("sampling erased degraded state")
	}
}
