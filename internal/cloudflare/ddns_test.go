package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestDDNSMigrationsRollbackExactPreviousRecord(t *testing.T) {
	for _, pair := range [][4]string{
		{"A", "8.8.8.8", "CNAME", "DDNS.EXAMPLE.COM."},
		{"AAAA", "2001:4860:4860::8888", "CNAME", "ddns.example.com"},
		{"CNAME", "old-ddns.example.com", "A", "1.1.1.1"},
		{"CNAME", "old-ddns.example.com", "AAAA", "2001:4860:4860::8888"},
		{"CNAME", "old-ddns.example.com", "CNAME", "ddns.example.com"},
	} {
		t.Run(pair[0]+"-to-"+pair[2], func(t *testing.T) {
			before := Record{ID: "r", Type: pair[0], Name: "node.example.com", Content: pair[1], TTL: 300, Comment: "original"}
			current, updates := before, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PUT" {
					updates++
					if err := json.NewDecoder(r.Body).Decode(&current); err != nil {
						t.Error(err)
					}
					current.ID = "r"
				}
				var result any = current
				if r.Method == "GET" && !strings.HasSuffix(r.URL.Path, "/r") {
					result = []Record{current}
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result, "result_info": map[string]int{"total_pages": 1}})
			}))
			defer server.Close()
			client := &Client{BaseURL: server.URL, Token: "test", HTTP: server.Client()}
			op := Operation{InstallationID: "mine", ZoneID: "z", Previous: &before, Desired: Record{Type: pair[2], Name: before.Name, Content: pair[3], TTL: 1, Proxied: true}}
			save := func() error { return nil }
			if _, err := Ensure(context.Background(), client, &op, save); err != nil {
				t.Fatal(err)
			}
			if current.Type != pair[2] || current.Content != strings.ToLower(strings.TrimSuffix(pair[3], ".")) || !current.Proxied {
				t.Fatal("wrong migration", current)
			}
			if err := Rollback(context.Background(), client, &op, save); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(current, before) || updates != 2 {
				t.Fatal("previous record not restored", current)
			}
		})
	}
}

func TestDDNSIntentRejectsInvalidTarget(t *testing.T) {
	for _, content := range []string{"NODE.EXAMPLE.COM.", "https://ddns.example.com", "ddns.example.com:443", "8.8.8.8", "256.1.1.1", "localhost"} {
		op := Operation{InstallationID: "mine", ZoneID: "z", Desired: Record{Type: "CNAME", Name: "node.example.com", Content: content}}
		if _, err := desired(&op); err == nil {
			t.Errorf("accepted CNAME target %q", content)
		}
	}
}

func TestDDNSEqualityUsesDNSNameSemantics(t *testing.T) {
	a := Record{ID: "r", Type: "CNAME", Name: "node.example.com", Content: "DDNS.EXAMPLE.COM."}
	b := a
	b.Content = "ddns.example.com"
	if !Equal(a, b) {
		t.Fatal("equivalent DNS target treated as external change")
	}
	b.Content = "other.example.com"
	if Equal(a, b) {
		t.Fatal("different DNS target treated as owned")
	}
}
