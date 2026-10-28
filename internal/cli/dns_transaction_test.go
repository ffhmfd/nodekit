package cli

import (
	"context"
	"errors"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"testing"
)

type memoryDNS struct {
	record     *cloudflare.Record
	deletes    int
	failDelete bool
}

func (m *memoryDNS) Records(context.Context, string, string) ([]cloudflare.Record, error) {
	if m.record == nil {
		return nil, nil
	}
	return []cloudflare.Record{*m.record}, nil
}
func (m *memoryDNS) Get(context.Context, string, string) (cloudflare.Record, error) {
	if m.record == nil {
		return cloudflare.Record{}, cloudflare.ErrNotFound
	}
	return *m.record, nil
}
func (m *memoryDNS) Create(_ context.Context, _ string, r cloudflare.Record) (cloudflare.Record, error) {
	r.ID = "record"
	m.record = &r
	return r, nil
}
func (m *memoryDNS) Update(_ context.Context, _ string, r cloudflare.Record) (cloudflare.Record, error) {
	m.record = &r
	return r, nil
}
func (m *memoryDNS) Delete(context.Context, string, string) error {
	if m.failDelete {
		return errors.New("DNS offline")
	}
	m.record = nil
	m.deletes++
	return nil
}

func TestDNSCommitResponseLossIsReconciled(t *testing.T) {
	for _, landed := range []bool{false, true} {
		t.Run(map[bool]string{false: "not-committed", true: "committed"}[landed], func(t *testing.T) {
			old, _ := model.New()
			old.Address = "8.8.8.8"
			next := old.Clone()
			next.ManagedDNS = true
			m := hostManifest{InstallationID: "instance"}
			api := &memoryDNS{}
			saves := 0
			save := func() error { saves++; return nil }
			if err := prepareDNSChange(context.Background(), api, &m, old, next, "zone", nil, save); err != nil {
				t.Fatal(err)
			}
			current := old
			submit := func(context.Context, model.Config) error {
				if landed {
					current = next
					current.Revision++
				}
				return context.Canceled
			}
			view := func(context.Context) (model.Config, error) { return current, nil }
			applied, err := commitDNSChange(context.Background(), api, &m, save, submit, view)
			if err == nil || applied != landed || saves < 2 {
				t.Fatal("lost response mishandled", applied, err)
			}
			if landed {
				if api.record == nil || api.deletes != 0 || len(m.DNSRecords) != 1 || m.DNSOperation != nil {
					t.Fatal("committed DNS was rolled back")
				}
			} else if api.record != nil || api.deletes != 1 || m.DNSOperation != nil {
				t.Fatal("uncommitted DNS was retained")
			}
		})
	}
}

func TestDNSUnknownConfigOutcomeRetainsRecovery(t *testing.T) {
	old, _ := model.New()
	old.Address = "8.8.8.8"
	next := old.Clone()
	next.ManagedDNS = true
	m := hostManifest{InstallationID: "instance"}
	api := &memoryDNS{}
	save := func() error { return nil }
	if err := prepareDNSChange(context.Background(), api, &m, old, next, "zone", nil, save); err != nil {
		t.Fatal(err)
	}
	_, err := commitDNSChange(context.Background(), api, &m, save, func(context.Context, model.Config) error { return context.Canceled }, func(context.Context) (model.Config, error) { return model.Config{}, errors.New("manager offline") })
	if !errors.Is(err, cloudflare.ErrUncertain) || m.DNSOperation == nil || api.record == nil {
		t.Fatal("uncertain transaction discarded", err)
	}
}

func TestObserveConfigCommitAfterCanceledResponse(t *testing.T) {
	old, _ := model.New()
	next := old.Clone()
	next.Name = "renamed"
	current := next.Clone()
	current.Revision++
	if applied, err := observeConfigCommit(old, next, current); err != nil || !applied {
		t.Fatal("lost successful response not recognized", err)
	}
	if applied, err := observeConfigCommit(old, next, old); err != nil || applied {
		t.Fatal("uncommitted update reported as applied", err)
	}
	current.Name = "other actor"
	if _, err := observeConfigCommit(old, next, current); !errors.Is(err, cloudflare.ErrUncertain) {
		t.Fatal("ambiguous outcome allowed rollback", err)
	}
}
