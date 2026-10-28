package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"nodekit/internal/cert"
	"nodekit/internal/manager"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type certificateBackend interface {
	View(context.Context) (store.Record, error)
	Change(context.Context, model.Config) error
}
type certificateController struct {
	db      *store.Store
	backend certificateBackend
	paths   paths
	runtime runtimeConfig
	issuer  cert.Issuer
	mu      sync.Mutex
}
type managedBackend struct {
	*manager.Manager
	certificates *certificateController
}

func (b managedBackend) Renew(ctx context.Context, domain string) error {
	return b.certificates.Renew(ctx, domain)
}

func (b managedBackend) ChangeManaged(ctx context.Context, c model.Config) error {
	r, err := b.Manager.View(ctx)
	if err != nil {
		return err
	}
	if r.Config.Domain != c.Domain {
		return b.certificates.RenewConfig(ctx, c)
	}
	return b.Manager.ChangeManaged(ctx, c)
}

func (c *certificateController) Renew(ctx context.Context, domain string) error {
	return c.renew(ctx, domain, nil)
}
func (c *certificateController) RenewConfig(ctx context.Context, next model.Config) error {
	return c.renew(ctx, next.Domain, &next)
}
func (c *certificateController) renew(ctx context.Context, domain string, candidate *model.Config) error {
	if !c.mu.TryLock() {
		return errors.New("certificate renewal already running")
	}
	defer c.mu.Unlock()
	if c.runtime.TokenFile == "" {
		return errors.New("DNS credentials are not configured; imported certificate needs manual renewal")
	}
	r, e := c.backend.View(ctx)
	if e != nil {
		return e
	}
	originalDomain := r.Config.Domain
	if domain == "" {
		domain = originalDomain
	}
	validation := r.Config
	if candidate != nil {
		if e = candidate.Validate(); e != nil {
			return e
		}
		if candidate.Revision != r.Config.Revision {
			return errors.New("stale configuration revision")
		}
		validation = *candidate
	} else if r.Config.ManagedDNS && domain != originalDomain {
		return errors.New("managed domain changes require the root DNS coordinator")
	}
	if !model.ValidDomain(domain) {
		return errors.New("invalid certificate domain")
	}
	if domain != originalDomain {
		if e = validateDomainAddress(ctx, validation.EffectiveSubscriptionMode(), domain, validation.Address, net.DefaultResolver.LookupIPAddr); e != nil {
			return e
		}
	}
	now := time.Now().UTC()
	if e = c.db.Update(func(r *store.Record) error {
		r.Certificate.LastAttempt = now
		r.Certificate.Mode = "automatic"
		return nil
	}); e != nil {
		return e
	}
	failure := func(cause error) error {
		writeErr := c.db.Update(func(r *store.Record) error {
			r.Certificate.Failures++
			shift := r.Certificate.Failures - 1
			if shift > 4 {
				shift = 4
			}
			r.Certificate.NextAttempt = time.Now().UTC().Add(time.Hour * time.Duration(1<<shift))
			r.Certificate.Error = "certificate issuance or activation failed; previous certificate retained"
			return nil
		})
		return errors.Join(cause, writeErr)
	}
	issuer := c.issuer
	if issuer == nil {
		issuer = cert.ACME{}
	}
	bundle, e := issuer.Obtain(ctx, cert.Options{Domain: domain, Email: c.runtime.Email, TokenFile: c.runtime.TokenFile, DirectoryURL: c.runtime.DirectoryURL, StateDir: filepath.Join(c.paths.Data, "acme")})
	if e != nil {
		return failure(e)
	}
	latest, e := c.backend.View(ctx)
	if e != nil {
		return failure(e)
	}
	if latest.Config.Domain != originalDomain || latest.Config.EffectiveSubscriptionMode() != r.Config.EffectiveSubscriptionMode() || latest.Config.Address != r.Config.Address {
		return failure(errors.New("domain, subscription mode or address changed during issuance; retry with current configuration"))
	}
	if candidate != nil && latest.Config.Revision != candidate.Revision {
		return failure(errors.New("configuration changed during coordinated issuance"))
	}
	id, e := cert.Store(filepath.Join(c.paths.Data, "certs"), bundle, domain, time.Now())
	if e != nil {
		return failure(e)
	}
	oldID := latest.Config.CertID
	if candidate != nil {
		latest.Config = candidate.Clone()
	}
	latest.Config.Domain = domain
	latest.Config.CertID = id
	change := c.backend.Change
	if candidate != nil {
		managed, ok := c.backend.(interface {
			ChangeManaged(context.Context, model.Config) error
		})
		if !ok {
			return failure(errors.New("DNS coordination unavailable"))
		}
		change = managed.ChangeManaged
	}
	if e = change(ctx, latest.Config); e != nil {
		return failure(e)
	}
	if e = c.db.Update(func(r *store.Record) error {
		r.Certificate = store.CertificateStatus{Expires: bundle.NotAfter, LastAttempt: now, NextAttempt: time.Now().UTC().Add(24 * time.Hour), Mode: "automatic"}
		return nil
	}); e != nil {
		return e
	}
	return c.prune(id, oldID)
}
func (c *certificateController) prune(keep ...string) error {
	allowed := map[string]bool{}
	for _, id := range keep {
		allowed[id] = true
	}
	root := filepath.Join(c.paths.Data, "certs")
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		id := entry.Name()
		if allowed[id] || !entry.IsDir() || len(id) != 64 {
			continue
		}
		if _, e = hex.DecodeString(id); e != nil {
			continue
		}
		if e = os.RemoveAll(filepath.Join(root, id)); e != nil {
			return e
		}
	}
	return nil
}
func (c *certificateController) run(ctx context.Context) {
	delay := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = 24 * time.Hour
		r, e := c.db.Load()
		if e != nil {
			delay = time.Hour
			continue
		}
		bundle, e := cert.Load(filepath.Join(c.paths.Data, "certs"), r.Config.CertID)
		if c.runtime.TokenFile == "" {
			_ = c.db.Update(func(r *store.Record) error {
				r.Certificate.Mode = "manual"
				r.Certificate.NextAttempt = time.Time{}
				if e == nil {
					r.Certificate.Expires = bundle.NotAfter
				}
				if e != nil || !bundle.NotAfter.After(time.Now()) {
					r.Certificate.Error = "imported certificate is unavailable or expired"
				}
				return nil
			})
			continue
		}
		if e == nil && time.Until(bundle.NotAfter) > 30*24*time.Hour {
			_ = c.db.Update(func(r *store.Record) error {
				r.Certificate.Mode = "automatic"
				r.Certificate.Expires = bundle.NotAfter
				if r.Certificate.Error == "" {
					r.Certificate.NextAttempt = time.Now().UTC().Add(delay)
				}
				return nil
			})
			continue
		}
		if r.Certificate.NextAttempt.After(time.Now()) && r.Certificate.Error != "" {
			delay = time.Until(r.Certificate.NextAttempt)
			continue
		}
		issue, cancel := context.WithTimeout(ctx, 10*time.Minute)
		_ = c.Renew(issue, "")
		cancel()
		latest, err := c.db.Load()
		if err == nil && latest.Certificate.NextAttempt.After(time.Now()) {
			delay = time.Until(latest.Certificate.NextAttempt)
		} else {
			delay = time.Hour
		}
	}
}
