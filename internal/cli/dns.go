package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func dnsZone(ctx context.Context, client *cloudflare.Client, domain string) (string, error) {
	zones, err := client.Zones(ctx)
	if err != nil {
		return "", err
	}
	var selected cloudflare.Zone
	for _, z := range zones {
		if z.Status == "active" && strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(z.Name)) && len(z.Name) > len(selected.Name) {
			selected = z
		}
	}
	if selected.ID == "" {
		return "", errors.New("no accessible active zone for this dedicated subdomain")
	}
	return selected.ID, nil
}

func rootConfig(ctx context.Context, p paths) (model.Config, error) {
	var c model.Config
	if err := p.admin(ctx, "GET", "/config", nil, &c); err == nil {
		return c, nil
	}
	if p.Root == "/" {
		return serviceConfig(ctx, p)
	}
	if _, err := os.Stat(filepath.Join(p.Data, "state.db")); err != nil {
		return c, err
	}
	db, err := p.db()
	if err != nil {
		return c, err
	}
	defer db.Close()
	r, err := db.Load()
	if err != nil {
		return c, err
	}
	return r.Config, r.Config.Validate()
}

func dnsClient(p paths) (*cloudflare.Client, error) {
	rt, err := p.runtime()
	if err != nil {
		return nil, err
	}
	return cloudflare.New(rt.TokenFile)
}

// Called with the host operation lock already held by edit/dns command.
func editDNS(ctx context.Context, p paths, old, next model.Config, adopt bool) (bool, error) {
	if os.Geteuid() != 0 {
		return false, errors.New("managed DNS changes require root")
	}
	m, err := loadHost(p)
	if err != nil {
		return false, err
	}
	if p.Root == "/" {
		if err = verifyAccount(p, m); err != nil {
			return false, err
		}
	}
	if m.DNSOperation != nil {
		return false, errors.New("unfinished DNS operation; run nodekit dns recover")
	}
	if m.PurgePhase != "" {
		return false, errors.New("purge is incomplete; resume uninstall --purge")
	}
	if !next.ManagedDNS {
		return false, errors.New("cannot detach managed DNS through config apply")
	}
	client, err := dnsClient(p)
	if err != nil {
		return false, err
	}
	zone, err := dnsZone(ctx, client, next.Domain)
	if err != nil {
		return false, err
	}
	var previous *cloudflare.Record
	for _, owned := range m.DNSRecords {
		if owned.ZoneID == zone && strings.EqualFold(owned.Record.Name, next.Domain) {
			r := owned.Record
			previous = &r
			break
		}
	}
	if previous == nil && adopt {
		rows, err := client.Records(ctx, zone, next.Domain)
		if err != nil {
			return false, err
		}
		if len(rows) > 1 {
			return false, cloudflare.ErrConflict
		}
		if len(rows) == 1 {
			r := rows[0]
			if r.Content != next.Address || r.Proxied != (next.EffectiveSubscriptionMode() == "cloudflare") || (r.Type != "A" && r.Type != "AAAA") {
				return false, errors.New("existing DNS does not match configured origin/mode; use setup to explicitly change it")
			}
			previous = &r
		}
	}
	save := func() error { return saveHost(p, m) }
	if err = prepareDNSChange(ctx, client, &m, old, next, zone, previous, save); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return false, errors.Join(err, abortDNSChange(cleanup, client, &m, save))
	}
	submit := func(ctx context.Context, c model.Config) error { return p.admin(ctx, "PUT", "/config/managed", c, nil) }
	view := func(ctx context.Context) (model.Config, error) {
		var c model.Config
		err := p.admin(ctx, "GET", "/config", nil, &c)
		return c, err
	}
	return commitDNSChange(ctx, client, &m, save, submit, view)
}

func recoverDNS(ctx context.Context, p paths, m *hostManifest, client cloudflare.API) error {
	if m.DNSOperation == nil {
		return nil
	}
	save := func() error { return saveHost(p, *m) }
	if m.DNSOperation.Old.Schema == 0 {
		if _, err := os.Stat(filepath.Join(p.Data, "state.db")); errors.Is(err, os.ErrNotExist) {
			return abortDNSChange(ctx, client, m, save)
		}
	}
	_, err := resolveDNSChange(ctx, client, m, save, func(ctx context.Context) (model.Config, error) { return rootConfig(ctx, p) })
	return err
}

func dnsCommand(ctx context.Context, p paths, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("dns status|adopt|recover")
	}
	if os.Geteuid() != 0 {
		return errors.New("DNS management requires root")
	}
	lock, err := operationLock(p)
	if err != nil {
		return err
	}
	defer lock.Close()
	m, err := loadHost(p)
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		for _, r := range m.DNSRecords {
			fmt.Fprintf(out, "托管 %s %s → %s，代理=%t\n", r.Record.Type, r.Record.Name, r.Record.Content, r.Record.Proxied)
		}
		if m.DNSOperation != nil {
			fmt.Fprintln(out, "待恢复DNS阶段:", m.DNSOperation.Phase)
		}
		return nil
	case "recover":
		client, err := dnsClient(p)
		if err != nil {
			return err
		}
		if err = recoverDNS(ctx, p, &m, client); err != nil {
			return err
		}
		fmt.Fprintln(out, "DNS操作已恢复")
		return nil
	case "adopt":
		old, err := rootConfig(ctx, p)
		if err != nil {
			return err
		}
		next := old.Clone()
		next.ManagedDNS = true
		_, err = editDNS(ctx, p, old, next, true)
		if err == nil {
			fmt.Fprintln(out, "DNS已登记；彻底卸载将删除该节点的登记记录")
		}
		return err
	}
	return errors.New("dns status|adopt|recover")
}
