package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"nodekit/internal/cert"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManualRenewDelegatesToServiceIdentity(t *testing.T) {
	root, e := os.MkdirTemp("", "nk-cert-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	p := makePaths(root, "")
	os.MkdirAll(p.Run, 0700)
	ln, e := net.Listen("unix", filepath.Join(p.Run, "admin.sock"))
	if e != nil {
		t.Fatal(e)
	}
	called := false
	config, _ := model.New()
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config" {
			json.NewEncoder(w).Encode(config)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/cert/renew" {
			called = true
			w.WriteHeader(204)
			return
		}
		http.NotFound(w, r)
	})}
	go s.Serve(ln)
	defer s.Close()
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--root", p.Root, "cert", "renew"}, bytes.NewReader(nil), io.Discard, &stderr); code != 0 || !called {
		t.Fatal("renewal not delegated", code, stderr.String())
	}
}

type failingIssuer struct{}

func (failingIssuer) Obtain(context.Context, cert.Options) (cert.Bundle, error) {
	return cert.Bundle{}, errors.New("provider failure")
}

type certBackend struct{ db *store.Store }

func (b certBackend) View(context.Context) (store.Record, error) { return b.db.Load() }
func (b certBackend) Change(_ context.Context, c model.Config) error {
	return b.db.Update(func(r *store.Record) error { r.Config = c; return nil })
}
func TestRenewalFailureIsPersistedWithoutChangingCertificate(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	db, e := p.db()
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	config, _ := model.New()
	config.CertID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	db.Update(func(r *store.Record) error { r.Config = config; return nil })
	ctl := certificateController{db: db, backend: certBackend{db}, paths: p, runtime: runtimeConfig{TokenFile: "configured"}, issuer: failingIssuer{}}
	if e = ctl.Renew(context.Background(), ""); e == nil {
		t.Fatal("renewal unexpectedly succeeded")
	}
	r, e := db.Load()
	if e != nil || r.Config.CertID != config.CertID || r.Certificate.Error == "" || !r.Certificate.NextAttempt.After(time.Now()) {
		t.Fatal("renewal failure disappeared", r.Certificate, e)
	}
}
