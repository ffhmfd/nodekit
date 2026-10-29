package httpapi

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"nodekit/internal/store"
)

func TestRoutingSubscriptionHTTPContract(t *testing.T) {
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "分流测试"
	c.CountryCode = "JP"
	c.Quota = 1000000000
	expiry := time.Unix(1700000000, 0) // Expiry/quota remain display-only.
	c.Expiry = &expiry
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless", "anytls"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
	b := &backend{r: store.Record{Config: c}}
	b.r.Meter.Upload, b.r.Meter.Download = 123, 456
	h := Subscription(b)
	var full, provider map[string]any
	for _, file := range []string{"config.yaml", "proxies.yaml"} {
		t.Run(file, func(t *testing.T) {
			path := "/s/" + c.Token + "/" + file
			want, err := render.Subscription(c, file == "proxies.yaml")
			if err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
				if w.Code != http.StatusOK {
					t.Fatalf("%s: status %d", method, w.Code)
				}
				for key, value := range map[string]string{
					"Subscription-Userinfo":   "upload=123; download=456; total=1000000000; expire=1700000000",
					"Profile-Title":           "base64:" + base64.StdEncoding.EncodeToString([]byte(c.Name)),
					"Profile-Update-Interval": "6", "Cache-Control": "no-store",
					"Content-Type": "application/yaml; charset=utf-8", "Content-Length": strconv.Itoa(len(want)),
				} {
					if got := w.Header().Get(key); got != value {
						t.Errorf("%s %s = %q, want %q", method, key, got, value)
					}
				}
				if method == http.MethodHead {
					if w.Body.Len() != 0 {
						t.Fatal("HEAD returned a body")
					}
					continue
				}
				if !bytes.Equal(w.Body.Bytes(), want) {
					t.Fatal("HTTP payload differs from the public renderer")
				}
				if strings.Contains(w.Body.String(), c.Reality.PrivateKey) || strings.Contains(w.Body.String(), c.Token) {
					t.Fatal("subscription exposed a server-only secret")
				}
				var payload map[string]any
				if err := yaml.Unmarshal(w.Body.Bytes(), &payload); err != nil {
					t.Fatal(err)
				}
				if file == "config.yaml" {
					full = payload
				} else {
					provider = payload
				}
			}
		})
	}
	if full == nil || provider == nil {
		t.Fatal("missing HTTP payload")
	}
	if len(provider) != 1 || !reflect.DeepEqual(full["proxies"], provider["proxies"]) || len(provider["proxies"].([]any)) != 7 {
		t.Fatal("provider must contain only the identical seven selected IPv4/IPv6 nodes")
	}
	if full["mode"] != "rule" || full["ipv6"] != true || len(full["proxy-groups"].([]any)) != 8 || len(full["rule-providers"].(map[string]any)) != 11 {
		t.Fatal("HTTP complete template omitted routing policy")
	}
	rules := full["rules"].([]any)
	if len(rules) != 26 || rules[0] != "GEOSITE,youtube,▶️ YouTube" || rules[1] != "OR,((DOMAIN,gemini.google.com),(DOMAIN,bard.google.com),(GEOSITE,openai)),🤖 ChatGPT" || rules[8] != "RULE-SET,apple,节点选择" || rules[len(rules)-1] != "MATCH,🐟 漏网之鱼" {
		t.Fatal("HTTP complete template omitted ordered business rules")
	}
	dns := full["dns"].(map[string]any)
	if dns["enhanced-mode"] != "fake-ip" || dns["ipv6"] != true || !reflect.DeepEqual(dns["fake-ip-filter"], []any{"*", "+.lan", "+.local"}) || full["sniffer"].(map[string]any)["enable"] != true {
		t.Fatal("HTTP complete template omitted DNS/sniffer policy")
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, file := range []string{"config.yaml", "proxies.yaml"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(method, "/s/wrong-token/"+file, nil))
			if w.Code != http.StatusNotFound || w.Header().Get("Subscription-Userinfo") != "" {
				t.Errorf("%s %s: wrong-token route exposed a subscription", method, file)
			}
		}
	}
	// Rotating the original token invalidates both original routes, not just config.yaml.
	b.r.Config.Token, err = model.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"config.yaml", "proxies.yaml"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/s/"+c.Token+"/"+file, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("old-token %s remained active", file)
		}
	}
}
