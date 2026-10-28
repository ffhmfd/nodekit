package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"nodekit/internal/cloudflare"
	"nodekit/internal/platform"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

func preparePurgeDNS(ctx context.Context, p paths, m *hostManifest, out io.Writer) (*cloudflare.Client, error) {
	if m.PurgePhase != "" && m.PurgePhase != "prepared" {
		return nil, nil
	}
	rt, err := p.runtime()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && len(m.DNSRecords) == 0 && m.DNSOperation == nil {
			if _, dbErr := os.Stat(filepath.Join(p.Data, "state.db")); errors.Is(dbErr, os.ErrNotExist) {
				return nil, nil
			}
		}
		return nil, err
	}
	var client *cloudflare.Client
	if rt.TokenFile != "" {
		client, err = cloudflare.New(rt.TokenFile)
		if err != nil {
			return nil, err
		}
	}
	if m.DNSOperation != nil {
		if client == nil {
			return nil, errors.New("DNS credentials required for recovery")
		}
		if err = recoverDNS(ctx, p, m, client); err != nil {
			return nil, err
		}
	}
	if len(m.DNSRecords) == 0 && m.PurgePhase == "" {
		if _, err = os.Stat(filepath.Join(p.Data, "state.db")); errors.Is(err, os.ErrNotExist) {
			return client, nil
		} else if err != nil {
			return nil, err
		}
		c, err := rootConfig(ctx, p)
		if err != nil {
			return nil, err
		}
		if client == nil {
			if c.ManagedDNS || c.EffectiveSubscriptionMode() == "cloudflare" {
				return nil, errors.New("provide Cloudflare credentials to identify and remove this node's DNS before purge")
			}
			fmt.Fprintln(out, "手动DNS/导入证书安装：没有登记Cloudflare记录，清理本地项目资源。")
			return nil, nil
		}
		zone, err := dnsZone(ctx, client, c.Domain)
		if err != nil {
			return nil, err
		}
		m.DNSRecords, err = discoverLegacyDNS(ctx, client, zone, c)
		if err != nil {
			return nil, err
		}
		if err = saveHost(p, *m); err != nil {
			return nil, err
		}
	}
	if len(m.DNSRecords) > 0 && client == nil {
		return nil, errors.New("DNS credentials required before removing tracked records")
	}
	for _, r := range m.DNSRecords {
		fmt.Fprintf(out, "将删除DNS: %s %s → %s（记录%s）\n", r.Record.Type, r.Record.Name, r.Record.Content, r.Record.ID)
	}
	return client, nil
}

func purgeCommand(ctx context.Context, p paths, out io.Writer) error {
	if p.Root != "/" || os.Geteuid() != 0 {
		return errors.New("彻底卸载需真实系统root；隔离验证使用purge操作边界")
	}
	lock, err := operationLock(p)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = owned(p.Opt); err != nil {
		return err
	}
	m, err := loadHost(p)
	if errors.Is(err, os.ErrNotExist) {
		if _, err = os.Stat(filepath.Join(p.Data, "state.db")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("database exists without ownership manifest; refusing purge")
		}
		if err = removePurgeCredentials(p); err != nil {
			return err
		}
		for _, dir := range []string{p.Data, p.Run, p.Etc} {
			if owned(dir) == nil {
				if err = os.RemoveAll(dir); err != nil {
					return err
				}
			}
		}
		if target, e := os.Readlink(filepath.Join(p.Root, "usr/local/bin/nodekit")); e == nil && target == filepath.Join(p.Opt, "current/nodekit") {
			if err = os.Remove(filepath.Join(p.Root, "usr/local/bin/nodekit")); err != nil {
				return err
			}
		}
		return os.RemoveAll(p.Opt)
	}
	if err != nil {
		return err
	}
	if _, e := user.Lookup("nodekit"); e == nil {
		if err = verifyAccount(p, m); err != nil {
			return err
		}
	} else if _, missing := e.(user.UnknownUserError); !missing {
		return e
	}
	if err = checkOwnedFiles(m); err != nil {
		return err
	}
	for _, dir := range []string{p.Etc, p.Data} {
		if err = owned(dir); err != nil {
			if m.PurgePhase == "" || !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	client, err := preparePurgeDNS(ctx, p, &m, out)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "彻底卸载包括 /root/nodekit-cloudflare.token 和项目内部凭据；不会撤销Cloudflare API Token。")
	ops := purgeOps{DNS: client, Save: func() error { return saveHost(p, m) }}
	ops.Stop = func(ctx context.Context) error {
		if err := checkOwnedFiles(m); err != nil {
			return err
		}
		var units []string
		for _, name := range []string{"nodekit-manager.service", "nodekit-core.service"} {
			if _, e := os.Stat(filepath.Join(p.Root, "etc/systemd/system", name)); e == nil {
				units = append(units, name)
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			} else if _, e = platform.Exec(ctx, "systemctl", "is-active", "--quiet", name); e == nil {
				return errors.New("active unit has no owned file")
			}
		}
		if len(units) == 0 {
			return nil
		}
		_, err := platform.Exec(ctx, append([]string{"systemctl", "disable", "--now"}, units...)...)
		return err
	}
	ops.Firewall = func(ctx context.Context) error {
		rules := m.Firewall
		if m.PendingFirewall != nil {
			rules = bindingsUnion(rules, bindingsUnion(m.PendingFirewall.Old, m.PendingFirewall.New))
		}
		if len(rules) == 0 {
			return nil
		}
		rt, err := p.runtime()
		if err != nil {
			return err
		}
		if rt.Firewall == "manual" {
			return nil
		}
		return (platform.Firewall{}).Remove(ctx, rules)
	}
	ops.Files = func(ctx context.Context) error {
		if err := checkOwnedFiles(m); err != nil {
			return err
		}
		for file := range m.Files {
			if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		link := filepath.Join(p.Root, "usr/local/bin/nodekit")
		if target, e := os.Readlink(link); e == nil && target == filepath.Join(p.Opt, "current/nodekit") {
			if e = os.Remove(link); e != nil {
				return e
			}
		}
		_, err := platform.Exec(ctx, "systemctl", "daemon-reload")
		return err
	}
	ops.Data = func(context.Context) error {
		if err := removePurgeRuntime(p, m); err != nil {
			return err
		}
		return removePurgeData(p, &m, ops.Save)
	}
	ops.Account = func(ctx context.Context) error {
		if _, e := user.Lookup("nodekit"); e == nil {
			if e = verifyAccount(p, m); e != nil {
				return e
			}
			if _, e = platform.Exec(ctx, "userdel", "nodekit"); e != nil {
				return e
			}
		} else if _, missing := e.(user.UnknownUserError); !missing {
			return e
		}
		if group, e := user.LookupGroup("nodekit"); e == nil {
			if group.Gid != strconv.Itoa(m.GID) {
				return errors.New("owned group identity changed")
			}
			_, e = platform.Exec(ctx, "groupdel", "nodekit")
			return e
		} else if _, missing := e.(user.UnknownGroupError); !missing {
			return e
		}
		return nil
	}
	ops.Credentials = func(context.Context) error { return removePurgeCredentials(p) }
	ops.Finish = func(context.Context) error {
		if err := os.RemoveAll(p.Etc); err != nil {
			return err
		}
		return os.RemoveAll(p.Opt)
	}
	if err = runPurge(ctx, &m, ops); err != nil {
		fmt.Fprintf(out, "卸载未完成（%s）。重试 /opt/nodekit/current/nodekit uninstall --purge\n", m.PurgePhase)
		return err
	}
	fmt.Fprintln(out, "NodeKit、登记DNS、标准Token文件和项目数据已彻底卸载；API Token未撤销。")
	return nil
}
