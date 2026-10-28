package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestClientPaginationAndRedactedErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-private-token" {
			t.Error("missing authorization")
		}
		if r.URL.Path == "/zones" {
			n, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
			if n < 5 || n > 50 {
				http.Error(w, "zone page size must be 5..50", 400)
				return
			}
			page := r.URL.Query().Get("page")
			fmt.Fprintf(w, `{"success":true,"result":[{"id":"z%s","name":"example%s.com","status":"active"}],"result_info":{"page":%s,"total_pages":2}}`, page, page, page)
			return
		}
		w.WriteHeader(403)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":9109,"message":"sensitive test-private-token"}]}`)
	}))
	defer server.Close()
	client := &Client{BaseURL: server.URL, Token: "test-private-token", HTTP: server.Client()}
	zones, err := client.Zones(context.Background())
	if err != nil || len(zones) != 2 || zones[1].ID != "z2" {
		t.Fatal(zones, err)
	}
	_, err = client.Records(context.Background(), "z1", "node.example.com")
	if err == nil || strings.Contains(err.Error(), "test-private-token") || !strings.Contains(err.Error(), "403") {
		t.Fatal("unredacted/incorrect API error", err)
	}
}

func TestCreateRecoveryAndExactDeletion(t *testing.T) {
	var stored *Record
	creates, deletes := 0, 0
	intentSaved := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zones/z/dns_records" && r.URL.Path != "/zones/z/dns_records/r" {
			t.Error("unexpected API path", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case "GET":
			if strings.HasSuffix(r.URL.Path, "/r") {
				if stored == nil {
					http.NotFound(w, r)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "result": stored})
				return
			}
			records := []Record{}
			if stored != nil {
				records = append(records, *stored)
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": records, "result_info": map[string]int{"total_pages": 1}})
		case "POST":
			if !intentSaved {
				t.Error("remote write before durable intent")
			}
			creates++
			var v Record
			json.NewDecoder(r.Body).Decode(&v)
			v.ID = "r"
			stored = &v
			// Simulate a response lost after Cloudflare committed the write.
			w.WriteHeader(502)
		case "DELETE":
			deletes++
			stored = nil
			fmt.Fprint(w, `{"success":true,"result":{"id":"r"}}`)
		default:
			t.Error("unexpected method", r.Method)
		}
	}))
	defer server.Close()
	client := &Client{BaseURL: server.URL, Token: "secret", HTTP: server.Client()}
	op := Operation{InstallationID: "installation-one", ZoneID: "z", Desired: Record{Type: "A", Name: "node.example.com", Content: "8.8.8.8", TTL: 1, Proxied: true}}
	save := func() error { intentSaved = true; return nil }
	owned, err := Ensure(context.Background(), client, &op, save)
	if err != nil || creates != 1 || owned.Record.ID != "r" {
		t.Fatal("unknown outcome not reconciled", owned, err)
	}
	if _, err = Ensure(context.Background(), client, &op, save); err != nil || creates != 1 {
		t.Fatal("retry duplicated DNS", err)
	}
	stored.Content = "1.1.1.1"
	if err = DeleteManaged(context.Background(), client, owned); !errors.Is(err, ErrConflict) || deletes != 0 {
		t.Fatal("deleted externally changed record", err)
	}
	stored.Content = "8.8.8.8"
	if err = DeleteManaged(context.Background(), client, owned); err != nil || deletes != 1 {
		t.Fatal(err)
	}
	if err = DeleteManaged(context.Background(), client, owned); err != nil || deletes != 1 {
		t.Fatal("delete not idempotent", err)
	}
}

func TestManagedRecordConflictAndSaveFailure(t *testing.T) {
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
			t.Error("unexpected mutation")
		}
		fmt.Fprint(w, `{"success":true,"result":[{"id":"foreign","type":"A","name":"node.example.com","content":"1.1.1.1","proxied":true,"ttl":1}],"result_info":{"total_pages":1}}`)
	}))
	defer server.Close()
	client := &Client{BaseURL: server.URL, Token: "secret", HTTP: server.Client()}
	op := Operation{InstallationID: "new", ZoneID: "z", Desired: Record{Type: "A", Name: "node.example.com", Content: "8.8.8.8", TTL: 1, Proxied: true}}
	if _, err := Ensure(context.Background(), client, &op, func() error { return nil }); !errors.Is(err, ErrConflict) || writes != 0 {
		t.Fatal("adopted foreign record", err)
	}
	if _, err := Ensure(context.Background(), client, &op, func() error { return errors.New("disk full") }); err == nil || writes != 0 {
		t.Fatal("ignored persistence failure")
	}
}

func TestAdoptRollbackAndCanceledRequest(t *testing.T) {
	before := Record{ID: "r", Type: "A", Name: "node.example.com", Content: "1.1.1.1", TTL: 300, Comment: "existing owner note"}
	current := before
	updates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			updates++
			var value Record
			json.NewDecoder(r.Body).Decode(&value)
			value.ID = "r"
			current = value
		}
		var result any = current
		if r.Method == "GET" && !strings.HasSuffix(r.URL.Path, "/r") {
			result = []Record{current}
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result, "result_info": map[string]int{"total_pages": 1}})
	}))
	defer server.Close()
	client := &Client{BaseURL: server.URL, Token: "secret", HTTP: server.Client()}
	op := Operation{InstallationID: "mine", ZoneID: "z", Previous: &before, Desired: Record{Type: "A", Name: before.Name, Content: "8.8.8.8", TTL: 1, Proxied: true}}
	if _, err := Ensure(context.Background(), client, &op, func() error { return nil }); err != nil || updates != 1 {
		t.Fatal(err)
	}
	if err := Rollback(context.Background(), client, &op, func() error { return nil }); err != nil || !reflect.DeepEqual(current, before) || updates != 2 {
		t.Fatal("prior record not restored", current, err)
	}
	if err := Rollback(context.Background(), client, &op, func() error { return nil }); err != nil || updates != 2 {
		t.Fatal("repeated compensation", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Zones(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request not honored", err)
	}
}
