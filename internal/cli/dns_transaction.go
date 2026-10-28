package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"time"
)

var errConfigApplied = errors.New("配置已生效；后续清理状态请查看管理状态")

func observeConfigCommit(old, next, current model.Config) (bool, error) {
	equal := func(a, b model.Config) bool {
		a.Revision = 0
		b.Revision = 0
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Equal(left, right)
	}
	if current.Revision > old.Revision && equal(next, current) {
		return true, nil
	}
	if current.Revision == old.Revision && equal(old, current) {
		return false, nil
	}
	return false, cloudflare.ErrUncertain
}

type dnsTransaction struct {
	Old             model.Config               `json:"old"`
	Next            model.Config               `json:"next"`
	Operation       cloudflare.Operation       `json:"operation"`
	PreviousRecords []cloudflare.ManagedRecord `json:"previous_records,omitempty"`
	Phase           string                     `json:"phase"`
}

func prepareDNSChange(ctx context.Context, api cloudflare.API, m *hostManifest, old, next model.Config, zone string, previous *cloudflare.Record, save func() error) error {
	if m.DNSOperation != nil {
		return errors.New("unfinished DNS operation; run nodekit dns recover")
	}
	if !next.ManagedDNS {
		return errors.New("coordinated configuration must keep managed DNS enabled")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(next.Address)
	if err != nil {
		return err
	}
	ip = ip.Unmap()
	typ := "A"
	if ip.Is6() {
		typ = "AAAA"
	}
	if m.InstallationID == "" {
		m.InstallationID, err = model.RandomToken()
		if err != nil {
			return err
		}
	}
	m.DNSOperation = &dnsTransaction{Old: old.Clone(), Next: next.Clone(), PreviousRecords: append([]cloudflare.ManagedRecord(nil), m.DNSRecords...), Phase: "prepared", Operation: cloudflare.Operation{
		InstallationID: m.InstallationID, ZoneID: zone, Previous: previous, Desired: cloudflare.Record{Type: typ, Name: next.Domain, Content: ip.String(), TTL: 1, Proxied: next.EffectiveSubscriptionMode() == "cloudflare"},
	}}
	if err = save(); err != nil {
		return err
	}
	if _, err = cloudflare.Ensure(ctx, api, &m.DNSOperation.Operation, save); err != nil {
		return err
	}
	m.DNSOperation.Phase = "dns_applied"
	return save()
}

func abortDNSChange(ctx context.Context, api cloudflare.API, m *hostManifest, save func() error) error {
	if m.DNSOperation == nil {
		return nil
	}
	if m.DNSOperation.Phase == "committed" {
		return errors.New("configuration already committed; finish DNS cleanup")
	}
	if err := cloudflare.Rollback(ctx, api, &m.DNSOperation.Operation, save); err != nil {
		return err
	}
	m.DNSOperation = nil
	return save()
}

func sameDNSRecord(a, b cloudflare.ManagedRecord) bool {
	return a.ZoneID == b.ZoneID && a.Record.ID == b.Record.ID
}

func completeDNSChange(ctx context.Context, api cloudflare.API, m *hostManifest, save func() error) error {
	if m.DNSOperation == nil {
		return nil
	}
	pending := m.DNSOperation
	if pending.Operation.Current == nil {
		return errors.New("DNS operation has no confirmed record")
	}
	managed := cloudflare.ManagedRecord{ZoneID: pending.Operation.ZoneID, Record: *pending.Operation.Current, Previous: pending.Operation.Previous, Created: pending.Operation.Previous == nil}
	// Publish the new ownership before removing any previous records. A failed
	// cleanup then retains both identities for retry or a complete purge.
	remaining := []cloudflare.ManagedRecord{managed}
	for _, old := range pending.PreviousRecords {
		if !sameDNSRecord(old, managed) {
			remaining = append(remaining, old)
		}
	}
	m.DNSRecords = remaining
	pending.Phase = "committed"
	if err := save(); err != nil {
		return err
	}
	for _, old := range pending.PreviousRecords {
		if sameDNSRecord(old, managed) {
			continue
		}
		if err := cloudflare.DeleteManaged(ctx, api, old); err != nil {
			return err
		}
	}
	m.DNSRecords = []cloudflare.ManagedRecord{managed}
	m.DNSOperation = nil
	return save()
}

func resolveDNSChange(ctx context.Context, api cloudflare.API, m *hostManifest, save func() error, view func(context.Context) (model.Config, error)) (bool, error) {
	if m.DNSOperation == nil {
		return false, nil
	}
	pending := m.DNSOperation
	current, err := view(ctx)
	if err != nil {
		return false, errors.Join(cloudflare.ErrUncertain, err)
	}
	if !model.DNSFieldsChanged(current, pending.Next) && (current.Revision > pending.Old.Revision || pending.Old.Schema == 0) {
		return true, completeDNSChange(ctx, api, m, save)
	}
	if pending.Phase != "committed" && !model.DNSFieldsChanged(current, pending.Old) {
		return false, abortDNSChange(ctx, api, m, save)
	}
	return false, cloudflare.ErrUncertain
}

func commitDNSChange(ctx context.Context, api cloudflare.API, m *hostManifest, save func() error, submit func(context.Context, model.Config) error, view func(context.Context) (model.Config, error)) (bool, error) {
	if m.DNSOperation == nil || m.DNSOperation.Phase != "dns_applied" {
		return false, errors.New("DNS is not ready for configuration commit")
	}
	m.DNSOperation.Phase = "submitting"
	if err := save(); err != nil {
		return false, err
	}
	err := submit(ctx, m.DNSOperation.Next)
	cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err == nil {
		return true, completeDNSChange(cleanup, api, m, save)
	}
	// Cancellation/connection loss does not prove that the daemon failed to
	// commit. Read its actual revision before compensating a remote DNS change.
	applied, reconcileErr := resolveDNSChange(cleanup, api, m, save, view)
	return applied, errors.Join(err, reconcileErr)
}
