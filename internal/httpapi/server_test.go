package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"strings"
	"testing"
	"time"
)

type backend struct{ r store.Record }

func (b *backend) View(context.Context) (store.Record, error)     { return b.r, nil }
func (b *backend) Reset(context.Context) error                    { b.r.Meter.Upload = 0; return nil }
func (b *backend) Change(_ context.Context, c model.Config) error { b.r.Config = c; return nil }
func TestSubscriptionContract(t *testing.T) {
	cfg, _ := model.New()
	expired := time.Unix(1700000000, 0)
	cfg.Expiry = &expired
	cfg.Quota = 100
	b := &backend{r: store.Record{Config: cfg}}
	b.r.Meter.Upload = 123
	b.r.Meter.Download = 456
	h := Subscription(b)
	path := "/s/" + cfg.Token + "/config.yaml"
	for _, method := range []string{"GET", "HEAD"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		if w.Code != 200 || w.Header().Get("Subscription-Userinfo") != "upload=123; download=456; total=100; expire=1700000000" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Header())
		}
		if method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD body")
		}
		if strings.Contains(w.Body.String(), cfg.Reality.PrivateKey) {
			t.Fatal("secret leaked")
		}
	}
	for _, path := range []string{"/usage/reset", "/s/bad/config.yaml", "/s/" + cfg.Token + "/../config.yaml"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal("unexpected public route", path, w.Code)
		}
	}
	b.r.Config.Token, _ = model.RandomToken()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 404 {
		t.Fatal("old token active")
	}
	b.r.Config.Quota = 0
	b.r.Config.Expiry = nil
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/s/"+b.r.Config.Token+"/proxies.yaml", nil))
	if w.Code != 200 || w.Header().Get("Subscription-Userinfo") != "upload=123; download=456" {
		t.Fatal("unset metadata", w.Header())
	}
}
