package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T, domain string, expiry time.Time) Bundle {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature}
	b, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	return Bundle{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), NotAfter: expiry}
}
func TestValidationAndImmutableVersions(t *testing.T) {
	root := t.TempDir()
	b := fixture(t, "node.example.com", time.Now().Add(48*time.Hour))
	if e := Validate(b, "node.example.com", time.Now()); e != nil {
		t.Fatal(e)
	}
	if Validate(b, "wrong.example.com", time.Now()) == nil {
		t.Fatal("wrong domain")
	}
	bad := fixture(t, "node.example.com", time.Now().Add(-time.Minute))
	if Validate(bad, "node.example.com", time.Now()) == nil {
		t.Fatal("expired accepted")
	}
	bad = b
	bad.PrivateKey = []byte("invalid")
	if Validate(bad, "node.example.com", time.Now()) == nil {
		t.Fatal("bad key")
	}
	id, e := Store(root, b, "node.example.com", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Store(root, bad, "node.example.com", time.Now()); e == nil {
		t.Fatal("bad update")
	}
	stored, e := os.ReadFile(filepath.Join(root, id, "cert.pem"))
	if e != nil || string(stored) != string(b.Certificate) {
		t.Fatal("old certificate changed")
	}
	info, e := os.Stat(filepath.Join(root, id, "key.pem"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("key permissions")
	}
}
