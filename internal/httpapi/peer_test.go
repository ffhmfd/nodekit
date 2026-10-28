package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"testing"
)

type managedTestBackend struct {
	backend
	calls int
}

func (b *managedTestBackend) ChangeManaged(ctx context.Context, c model.Config) error {
	b.calls++
	b.r.Config = c
	return nil
}

func TestManagedAPIRequiresUnixRootPeer(t *testing.T) {
	c, _ := model.New()
	c.ManagedDNS = true
	body, _ := json.Marshal(c)
	b := &managedTestBackend{backend: backend{r: store.Record{Config: c}}}
	handler := Admin(b)
	for _, uid := range []int{-1, 1000, 0} {
		req := httptest.NewRequest("PUT", "/config/managed", bytes.NewReader(body))
		req.Header.Set("X-NodeKit-UID", "0")
		if uid >= 0 {
			req = req.WithContext(context.WithValue(req.Context(), peerUIDKey{}, uid))
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if uid == 0 {
			if out.Code != 204 || b.calls != 1 {
				t.Fatal("root coordinator rejected", out.Code)
			}
		} else if out.Code != 403 || b.calls != 0 {
			t.Fatal("nonroot coordinator accepted", out.Code)
		}
	}
}
