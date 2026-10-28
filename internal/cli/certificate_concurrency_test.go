package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"nodekit/internal/cert"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"testing"
	"time"
)

type issuerFunc func(context.Context, cert.Options) (cert.Bundle, error)

func (f issuerFunc) Obtain(ctx context.Context, o cert.Options) (cert.Bundle, error) {
	return f(ctx, o)
}

func issuanceBundle(t *testing.T, domain string) cert.Bundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert.Bundle{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), NotAfter: expires}
}

func TestCertificateRejectsChangedValidationInputs(t *testing.T) {
	for _, field := range []string{"mode", "address"} {
		t.Run(field, func(t *testing.T) {
			p := makePaths(t.TempDir(), "")
			db, err := p.db()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			c, _ := model.New()
			c.SubscriptionMode = "cloudflare"
			c.SubscriptionPort = 8443
			c.Address = "8.8.8.8"
			if err = db.Update(func(r *store.Record) error { r.Config = c; r.Meter.Upload = 123; return nil }); err != nil {
				t.Fatal(err)
			}
			bundle := issuanceBundle(t, "new.invalid")
			entered, release := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			issuer := issuerFunc(func(ctx context.Context, o cert.Options) (cert.Bundle, error) {
				close(entered)
				select {
				case <-ctx.Done():
					return cert.Bundle{}, ctx.Err()
				case <-release:
					return bundle, nil
				}
			})
			ctl := certificateController{db: db, backend: certBackend{db}, paths: p, runtime: runtimeConfig{TokenFile: "configured"}, issuer: issuer}
			go func() { result <- ctl.Renew(ctx, "new.invalid") }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err = db.Update(func(r *store.Record) error {
				if field == "mode" {
					r.Config.SubscriptionMode = "direct"
				} else {
					r.Config.Address = "1.1.1.1"
				}
				r.Config.Revision++
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			close(release)
			select {
			case err = <-result:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err == nil {
				t.Fatal("published certificate using obsolete DNS validation")
			}
			r, err := db.Load()
			if err != nil {
				t.Fatal(err)
			}
			if r.Config.Domain != c.Domain || r.Config.CertID != c.CertID || r.Config.Revision != 2 || r.Meter.Upload != 123 {
				t.Fatal("failed publication changed configuration or usage")
			}
		})
	}
}
