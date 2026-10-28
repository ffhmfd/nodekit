package cloudflare

import (
	"context"
	"errors"
	"net/netip"
	"nodekit/internal/model"
	"strings"
)

var ErrConflict = errors.New("Cloudflare DNS record changed or belongs to another owner")
var ErrUncertain = errors.New("DNS write outcome is uncertain; credentials and recovery journal retained, retry reconciliation")

type API interface {
	Records(context.Context, string, string) ([]Record, error)
	Get(context.Context, string, string) (Record, error)
	Create(context.Context, string, Record) (Record, error)
	Update(context.Context, string, Record) (Record, error)
	Delete(context.Context, string, string) error
}
type ManagedRecord struct {
	ZoneID   string  `json:"zone_id"`
	Record   Record  `json:"record"`
	Previous *Record `json:"previous,omitempty"`
	Created  bool    `json:"created"`
}
type Operation struct {
	InstallationID string  `json:"installation_id"`
	ZoneID         string  `json:"zone_id"`
	Desired        Record  `json:"desired"`
	Previous       *Record `json:"previous,omitempty"`
	Current        *Record `json:"current,omitempty"`
	Phase          string  `json:"phase"`
}

func Equal(a, b Record) bool { return a.ID == b.ID && sameValues(a, b) }
func sameValues(a, b Record) bool {
	return a.Type == b.Type && strings.EqualFold(strings.TrimSuffix(a.Name, "."), strings.TrimSuffix(b.Name, ".")) && a.Content == b.Content && a.Proxied == b.Proxied && a.TTL == b.TTL && a.Comment == b.Comment
}
func desired(op *Operation) (Record, error) {
	r := op.Desired
	r.ID = ""
	r.Name = strings.ToLower(strings.TrimSuffix(r.Name, "."))
	if !idRE.MatchString(op.InstallationID) || len(op.InstallationID) > 64 || !idRE.MatchString(op.ZoneID) || !model.ValidDomain(r.Name) {
		return r, errors.New("invalid managed DNS intent")
	}
	ip, err := netip.ParseAddr(r.Content)
	if err != nil || ip.Zone() != "" {
		return r, errors.New("invalid DNS origin IP")
	}
	ip = ip.Unmap()
	r.Content = ip.String()
	if (ip.Is4() && r.Type != "A") || (ip.Is6() && r.Type != "AAAA") {
		return r, errors.New("DNS type does not match origin address")
	}
	r.Comment = "nodekit:" + op.InstallationID
	if r.TTL == 0 {
		r.TTL = 1
	}
	return r, nil
}
func owned(op *Operation, r Record) ManagedRecord {
	return ManagedRecord{ZoneID: op.ZoneID, Record: r, Previous: op.Previous, Created: op.Previous == nil}
}

// Ensure persists an intent before every external mutation. A lost create
// response is reconciled by installation marker, never by blindly POSTing again.
func Ensure(ctx context.Context, api API, op *Operation, save func() error) (ManagedRecord, error) {
	want, err := desired(op)
	if err != nil {
		return ManagedRecord{}, err
	}
	if op.Phase == "rolled_back" {
		return ManagedRecord{}, errors.New("DNS operation was rolled back")
	}
	if op.Phase == "" {
		op.Phase = "prepared"
	}
	op.Desired = want
	if err = save(); err != nil {
		return ManagedRecord{}, err
	}
	records, err := api.Records(ctx, op.ZoneID, want.Name)
	if err != nil {
		return ManagedRecord{}, err
	}
	var found *Record
	for _, r := range records {
		if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), want.Name) {
			return ManagedRecord{}, ErrConflict
		}
		if sameValues(r, want) {
			copy := r
			found = &copy
			continue
		}
		if op.Previous != nil && Equal(r, *op.Previous) {
			continue
		}
		return ManagedRecord{}, ErrConflict
	}
	if found != nil {
		if len(records) != 1 {
			return ManagedRecord{}, ErrConflict
		}
		op.Current = found
		op.Phase = "applied"
		if err = save(); err != nil {
			return ManagedRecord{}, err
		}
		return owned(op, *found), nil
	}
	if op.Phase == "applied" {
		return ManagedRecord{}, ErrConflict
	}
	if op.Previous == nil && len(records) == 0 && (op.Phase == "creating" || op.Phase == "uncertain") {
		return ManagedRecord{}, ErrUncertain
	}
	var result Record
	if op.Previous != nil {
		if len(records) != 1 || !Equal(records[0], *op.Previous) {
			return ManagedRecord{}, ErrConflict
		}
		want.ID = op.Previous.ID
		op.Phase = "updating"
		if err = save(); err != nil {
			return ManagedRecord{}, err
		}
		result, err = api.Update(ctx, op.ZoneID, want)
	} else {
		if len(records) != 0 {
			return ManagedRecord{}, ErrConflict
		}
		op.Phase = "creating"
		if err = save(); err != nil {
			return ManagedRecord{}, err
		}
		result, err = api.Create(ctx, op.ZoneID, want)
	}
	if err != nil {
		cause := err
		if Rejected(err) {
			op.Phase = "prepared"
			return ManagedRecord{}, errors.Join(err, save())
		}
		op.Phase = "uncertain"
		if err = save(); err != nil {
			return ManagedRecord{}, errors.Join(cause, err)
		}
		check, lookupErr := api.Records(ctx, op.ZoneID, want.Name)
		if lookupErr != nil || len(check) != 1 || !sameValues(check[0], want) {
			return ManagedRecord{}, errors.Join(cause, ErrUncertain, lookupErr)
		}
		result = check[0]
	}
	if result.ID == "" || !sameValues(result, want) {
		return ManagedRecord{}, ErrUncertain
	}
	op.Current = &result
	op.Phase = "applied"
	if err = save(); err != nil {
		return ManagedRecord{}, err
	}
	return owned(op, result), nil
}

func DeleteManaged(ctx context.Context, api API, m ManagedRecord) error {
	current, err := api.Get(ctx, m.ZoneID, m.Record.ID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !Equal(current, m.Record) {
		return ErrConflict
	}
	err = api.Delete(ctx, m.ZoneID, m.Record.ID)
	if err == nil || errors.Is(err, ErrNotFound) {
		return nil
	}
	if _, probe := api.Get(ctx, m.ZoneID, m.Record.ID); errors.Is(probe, ErrNotFound) {
		return nil
	}
	return err
}

func Rollback(ctx context.Context, api API, op *Operation, save func() error) error {
	if op.Phase == "rolled_back" {
		return nil
	}
	want, err := desired(op)
	if err != nil {
		return err
	}
	rows, err := api.Records(ctx, op.ZoneID, want.Name)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		if op.Previous != nil {
			return ErrConflict
		}
		if op.Phase == "creating" || op.Phase == "uncertain" {
			return ErrUncertain
		}
	} else {
		if len(rows) != 1 {
			return ErrConflict
		}
		current := rows[0]
		if op.Previous != nil && Equal(current, *op.Previous) {
			op.Phase = "rolled_back"
			return save()
		}
		if !sameValues(current, want) {
			return ErrConflict
		}
		if op.Previous != nil {
			if _, err = api.Update(ctx, op.ZoneID, *op.Previous); err != nil {
				return err
			}
		} else if err = DeleteManaged(ctx, api, owned(op, current)); err != nil {
			return err
		}
	}
	op.Phase = "rolled_back"
	return save()
}
