package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"net/http"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Bundle struct {
	Certificate, PrivateKey []byte
	NotAfter                time.Time
}
type Options struct{ Domain, Email, TokenFile, DirectoryURL, StateDir string }
type Issuer interface {
	Obtain(context.Context, Options) (Bundle, error)
}
type ACME struct{}
type account struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	KeyPEM       []byte                 `json:"key_pem"`
	key          crypto.PrivateKey
}

func (a *account) GetEmail() string                        { return a.Email }
func (a *account) GetRegistration() *registration.Resource { return a.Registration }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

type boundTransport struct{ ctx context.Context }

func (t boundTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(r.WithContext(t.ctx))
}
func Validate(b Bundle, domain string, now time.Time) error {
	pair, e := tls.X509KeyPair(b.Certificate, b.PrivateKey)
	if e != nil {
		return errors.New("certificate/key mismatch or invalid PEM")
	}
	if len(pair.Certificate) == 0 {
		return errors.New("empty certificate")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return e
	}
	if e = leaf.VerifyHostname(domain); e != nil {
		return e
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("certificate is not currently valid")
	}
	return nil
}
func Store(root string, b Bundle, domain string, now time.Time) (string, error) {
	if e := Validate(b, domain, now); e != nil {
		return "", e
	}
	sum := sha256.Sum256(b.Certificate)
	id := hex.EncodeToString(sum[:])
	dir := filepath.Join(root, id)
	if e := os.MkdirAll(root, 0700); e != nil {
		return "", e
	}
	if _, e := os.Stat(dir); e == nil {
		old, e := Load(root, id)
		if e != nil {
			return "", e
		}
		if e = Validate(old, domain, now); e != nil {
			return "", e
		}
		return id, nil
	}
	tmp, e := os.MkdirTemp(root, ".issue-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(tmp)
	if e = os.WriteFile(filepath.Join(tmp, "cert.pem"), b.Certificate, 0600); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(tmp, "key.pem"), b.PrivateKey, 0600); e != nil {
		return "", e
	}
	for _, name := range []string{"cert.pem", "key.pem"} {
		f, e := os.OpenFile(filepath.Join(tmp, name), os.O_RDWR, 0)
		if e != nil {
			return "", e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return "", e
		}
	}
	if e = os.Rename(tmp, dir); e != nil {
		return "", e
	}
	d, e := os.Open(root)
	if e != nil {
		return "", e
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return "", e
	}
	return id, nil
}
func Load(root, id string) (Bundle, error) {
	if len(id) != 64 {
		return Bundle{}, errors.New("invalid certificate ID")
	}
	if _, e := hex.DecodeString(id); e != nil {
		return Bundle{}, e
	}
	b, e := os.ReadFile(filepath.Join(root, id, "cert.pem"))
	if e != nil {
		return Bundle{}, e
	}
	k, e := os.ReadFile(filepath.Join(root, id, "key.pem"))
	if e != nil {
		return Bundle{}, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return Bundle{}, errors.New("invalid certificate PEM")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return Bundle{}, e
	}
	return Bundle{b, k, leaf.NotAfter}, nil
}
func (ACME) Obtain(ctx context.Context, o Options) (Bundle, error) {
	if !model.ValidDomain(o.Domain) || o.Email == "" || o.TokenFile == "" {
		return Bundle{}, errors.New("domain, email and token file required")
	}
	if o.DirectoryURL == "" {
		o.DirectoryURL = lego.LEDirectoryProduction
	}
	if o.DirectoryURL != lego.LEDirectoryProduction && o.DirectoryURL != lego.LEDirectoryStaging {
		return Bundle{}, errors.New("unsupported ACME directory")
	}
	info, e := os.Stat(o.TokenFile)
	if e != nil {
		return Bundle{}, e
	}
	if info.Mode().Perm()&0007 != 0 {
		return Bundle{}, errors.New("token file is accessible to other users")
	}
	token, e := os.ReadFile(o.TokenFile)
	if e != nil {
		return Bundle{}, e
	}
	secret := strings.TrimSpace(string(token))
	if len(secret) < 10 {
		return Bundle{}, errors.New("invalid DNS token file")
	}
	sum := sha256.Sum256([]byte(o.DirectoryURL))
	stateDir := filepath.Join(o.StateDir, hex.EncodeToString(sum[:8]))
	if e = os.MkdirAll(stateDir, 0700); e != nil {
		return Bundle{}, e
	}
	accountPath := filepath.Join(stateDir, "account.json")
	a := &account{Email: o.Email}
	data, e := os.ReadFile(accountPath)
	if e == nil {
		if e = json.Unmarshal(data, a); e != nil {
			return Bundle{}, e
		}
		block, _ := pem.Decode(a.KeyPEM)
		if block == nil {
			return Bundle{}, errors.New("invalid saved ACME account")
		}
		a.key, e = x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return Bundle{}, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return Bundle{}, e
	} else {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return Bundle{}, e
		}
		a.key = k
		der, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			return Bundle{}, e
		}
		a.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	cfg := lego.NewConfig(a)
	cfg.CADirURL = o.DirectoryURL
	cfg.HTTPClient = &http.Client{Transport: boundTransport{ctx}, Timeout: 30 * time.Second}
	client, e := lego.NewClient(cfg)
	if e != nil {
		return Bundle{}, errors.New("ACME client initialization failed")
	}
	dns := cloudflare.NewDefaultConfig()
	dns.AuthToken = secret
	dns.ZoneToken = secret
	dns.HTTPClient = cfg.HTTPClient
	provider, e := cloudflare.NewDNSProviderConfig(dns)
	if e != nil {
		return Bundle{}, errors.New("DNS provider initialization failed")
	}
	if e = client.Challenge.SetDNS01Provider(provider); e != nil {
		return Bundle{}, e
	}
	save := func() error {
		b, e := json.Marshal(a)
		if e != nil {
			return e
		}
		tmp := accountPath + ".tmp"
		if e = os.WriteFile(tmp, b, 0600); e != nil {
			return e
		}
		return os.Rename(tmp, accountPath)
	}
	if e = save(); e != nil {
		return Bundle{}, e
	}
	if a.Registration == nil {
		a.Registration, e = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if e != nil {
			return Bundle{}, errors.New("ACME registration failed; check connectivity and email")
		}
		if e = save(); e != nil {
			return Bundle{}, e
		}
	}
	result, e := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{o.Domain}, Bundle: true})
	if e != nil {
		return Bundle{}, errors.New("DNS-01 issuance failed; check DNS permissions, propagation and CA limits")
	}
	b := Bundle{Certificate: result.Certificate, PrivateKey: result.PrivateKey}
	if e = Validate(b, o.Domain, time.Now()); e != nil {
		return Bundle{}, e
	}
	block, _ := pem.Decode(b.Certificate)
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return Bundle{}, e
	}
	b.NotAfter = leaf.NotAfter
	return b, nil
}
