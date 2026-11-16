package httpapi

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http/httptest"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"testing"
	"time"
)

func TestTrafficMultiplierAdminStatusKeepsRawCounters(t *testing.T) {
	cfg, _ := model.New()
	cfg.TrafficMultiplier = 2
	b := &backend{r: store.Record{Config: cfg}}
	b.r.Meter.Upload, b.r.Meter.Download = 10, 100
	w := httptest.NewRecorder()
	Admin(b).ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	var got store.Record
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Config.EffectiveTrafficMultiplier() != 2 || got.Meter.Upload != 10 || got.Meter.Download != 100 {
		t.Fatal("internal status lost raw semantics")
	}
}

func TestTrafficMultiplierSubscriptionReversible(t *testing.T) {
	cfg, _ := model.New()
	cfg.Quota = 1000
	expiry := time.Unix(1900000000, 0)
	cfg.Expiry = &expiry
	b := &backend{r: store.Record{Config: cfg}}
	b.r.Meter.Upload, b.r.Meter.Download = 10, 100
	h := Subscription(b)
	for _, step := range []struct {
		multiplier int
		want       string
	}{
		{0, "upload=10; download=100; total=1000; expire=1900000000"},
		{2, "upload=20; download=200; total=1000; expire=1900000000"},
		{1, "upload=10; download=100; total=1000; expire=1900000000"},
	} {
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"traffic_multiplier":%d}`, step.multiplier)), &b.r.Config); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"config.yaml", "proxies.yaml"} {
			for _, method := range []string{"GET", "HEAD"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, "/s/"+cfg.Token+"/"+file, nil))
				if w.Code != 200 || w.Header().Get("Subscription-Userinfo") != step.want {
					t.Errorf("%dx %s %s: %d %s", step.multiplier, method, file, w.Code, w.Header().Get("Subscription-Userinfo"))
				}
				if method == "HEAD" && w.Body.Len() != 0 {
					t.Fatal("HEAD body")
				}
			}
		}
		if b.r.Meter.Upload != 10 || b.r.Meter.Download != 100 {
			t.Fatal("raw usage modified")
		}
	}
}

func TestTrafficMultiplierSubscriptionLargeCounters(t *testing.T) {
	cfg, _ := model.New()
	if err := json.Unmarshal([]byte(`{"traffic_multiplier":2}`), &cfg); err != nil {
		t.Fatal(err)
	}
	b := &backend{r: store.Record{Config: cfg}}
	b.r.Meter.Upload, b.r.Meter.Download = math.MaxInt64, math.MaxInt64
	w := httptest.NewRecorder()
	Subscription(b).ServeHTTP(w, httptest.NewRequest("GET", "/s/"+cfg.Token+"/config.yaml", nil))
	if got := w.Header().Get("Subscription-Userinfo"); got != "upload=18446744073709551614; download=18446744073709551614" {
		t.Fatal("large counters overflowed", got)
	}
}
