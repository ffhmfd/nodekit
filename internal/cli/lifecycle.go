package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"nodekit/internal/core"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func owned(path string) error {
	return platform.Owned(path)
}
func operationLock(p paths) (*os.File, error) {
	return platform.AcquireLock(filepath.Join(p.Opt, "operation.lock"))
}
func services(ctx context.Context, verb string) error {
	_, e := platform.Exec(ctx, "systemctl", verb, "nodekit-core.service", "nodekit-manager.service")
	return e
}
func waitReady(ctx context.Context, p paths) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var c model.Config
		requestCtx, cancel := context.WithTimeout(ctx, time.Second)
		e := p.admin(requestCtx, "GET", "/config", nil, &c)
		cancel()
		if e == nil {
			probe, cancel := context.WithTimeout(ctx, time.Second)
			e = (&core.Client{Socket: p.render().Socket, WorkDir: p.Data, Binary: p.Core}).Health(probe, c)
			cancel()
			if e == nil {
				conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(c.SubscriptionPort)), &tls.Config{InsecureSkipVerify: true})
				if e == nil {
					conn.Close()
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("manager/core/HTTPS did not become ready")
}
func validReleaseTarget(target string) bool {
	return strings.HasPrefix(target, "releases/") && filepath.Dir(target) == "releases" && !strings.Contains(target, "..") && !strings.ContainsAny(target, "\x00\r\n")
}
func switchLink(base, name, target string) error {
	if !validReleaseTarget(target) {
		return errors.New("invalid release target")
	}
	f, e := os.CreateTemp(base, ".link-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	f.Close()
	os.Remove(tmp)
	if e = os.Symlink(target, tmp); e != nil {
		return e
	}
	defer os.Remove(tmp)
	if e = os.Rename(tmp, filepath.Join(base, name)); e != nil {
		return e
	}
	d, e := os.Open(base)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

type upgradeJournal struct{ Old, New, Previous, Phase string }

func lifecycleDir(p paths) string { return filepath.Join(p.Etc, "lifecycle") }
func writeJournal(p paths, j upgradeJournal) error {
	b, e := json.Marshal(j)
	if e != nil {
		return e
	}
	return platform.WritePrivate(filepath.Join(lifecycleDir(p), "upgrade.json"), b)
}
func readJournal(p paths) (upgradeJournal, error) {
	var j upgradeJournal
	b, e := platform.ReadPrivate(filepath.Join(lifecycleDir(p), "upgrade.json"))
	if e != nil {
		return j, e
	}
	e = json.Unmarshal(b, &j)
	if e != nil {
		return j, e
	}
	if !validReleaseTarget(j.Old) || !validReleaseTarget(j.New) || (j.Previous != "" && !validReleaseTarget(j.Previous)) {
		return j, errors.New("invalid lifecycle journal")
	}
	switch j.Phase {
	case "prepared", "backed_up", "switched", "committed":
	default:
		return j, errors.New("unknown lifecycle phase")
	}
	return j, nil
}
func clearJournal(p paths) error {
	for _, name := range []string{"upgrade.json", "state.db"} {
		if e := os.Remove(filepath.Join(lifecycleDir(p), name)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	return nil
}
func serviceTool(ctx context.Context, p paths, command string) ([]byte, error) {
	b, e := platform.Exec(ctx, "runuser", "-u", "nodekit", "--", filepath.Join(p.Opt, "previous/nodekit"), command)
	if e != nil {
		return nil, fmt.Errorf("service-identity %s failed", command)
	}
	return b, nil
}
func recoverUpgrade(ctx context.Context, p paths, boot bool) error {
	j, e := readJournal(p)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	m, e := loadHost(p)
	if e != nil {
		return e
	}
	if e = verifyAccount(p, m); e != nil {
		return e
	}
	if e = checkOwnedFiles(m); e != nil {
		return e
	}
	if j.Phase == "committed" {
		return clearJournal(p)
	}
	if boot {
		if _, e = platform.Exec(ctx, "systemctl", "stop", "nodekit-manager.service"); e != nil {
			return e
		}
	} else if e = services(ctx, "stop"); e != nil {
		return e
	}
	if j.Phase != "prepared" {
		data, e := platform.ReadPrivate(filepath.Join(lifecycleDir(p), "state.db"))
		if e != nil {
			return e
		}
		root, e := os.OpenRoot(p.Data)
		if e != nil {
			return e
		}
		for _, name := range []string{"state.db-wal", "state.db-shm"} {
			e = root.Remove(name)
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				root.Close()
				return e
			}
		}
		root.Close()
		if e = platform.RestoreAtomic(p.Data, "state.db", data, m.UID, m.GID); e != nil {
			return e
		}
	}
	if e = switchLink(p.Opt, "current", j.Old); e != nil {
		return e
	}
	if j.Previous != "" {
		if e = switchLink(p.Opt, "previous", j.Previous); e != nil {
			return e
		}
	} else {
		if e = switchLink(p.Opt, "previous", j.Old); e != nil {
			return e
		}
	}
	if _, e = serviceTool(ctx, p, "prepare"); e != nil {
		return e
	}
	if boot {
		_, e = platform.Exec(ctx, "systemctl", "--no-block", "start", "nodekit-manager.service")
		if e != nil {
			return e
		}
		return clearJournal(p)
	}
	if e = services(ctx, "start"); e != nil {
		return e
	}
	if e = waitReady(ctx, p); e != nil {
		return e
	}
	return clearJournal(p)
}
func recoverCommand(ctx context.Context, p paths, boot bool) error {
	if os.Geteuid() != 0 || p.Root != "/" {
		return errors.New("recovery requires system root")
	}
	lock, e := operationLock(p)
	if errors.Is(e, platform.ErrLocked) && boot {
		return nil
	}
	if e != nil {
		return e
	}
	defer lock.Close()
	return recoverUpgrade(ctx, p, boot)
}
func releaseCommand(ctx context.Context, p paths, args []string, out io.Writer) error {
	if os.Geteuid() != 0 || p.Root != "/" {
		return errors.New("升级/回滚需真实系统 root")
	}
	lock, e := operationLock(p)
	if e != nil {
		return e
	}
	defer lock.Close()
	m, e := loadHost(p)
	if e != nil {
		return e
	}
	if e = verifyAccount(p, m); e != nil {
		return e
	}
	if e = checkOwnedFiles(m); e != nil {
		return e
	}
	if _, e = readJournal(p); e == nil {
		return recoverUpgrade(ctx, p, false)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = owned(p.Opt); e != nil {
		return e
	}
	old, e := os.Readlink(filepath.Join(p.Opt, "current"))
	if e != nil || !validReleaseTarget(old) {
		return errors.New("unmanaged current release")
	}
	previous, e := os.Readlink(filepath.Join(p.Opt, "previous"))
	if e != nil {
		return e
	}
	target := ""
	if args[0] == "rollback" {
		target = previous
	} else {
		fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
		fs.SetOutput(out)
		archive := fs.String("file", "", "release archive")
		sha := fs.String("sha256", "", "trusted archive checksum")
		if e = fs.Parse(args[1:]); e != nil {
			return e
		}
		stage := filepath.Join(p.Opt, fmt.Sprintf(".stage-%d", time.Now().UnixNano()))
		meta, e := platform.ExtractRelease(*archive, stage, *sha)
		if e != nil {
			return e
		}
		defer os.RemoveAll(stage)
		target = fmt.Sprintf("releases/%s-%d", meta.Version, time.Now().UnixNano())
		if e = os.Chmod(stage, 0755); e != nil {
			return e
		}
		if e = os.Rename(stage, filepath.Join(p.Opt, target)); e != nil {
			return e
		}
		defer func() {
			current, _ := os.Readlink(filepath.Join(p.Opt, "current"))
			previous, _ := os.Readlink(filepath.Join(p.Opt, "previous"))
			if target != current && target != previous {
				_ = os.RemoveAll(filepath.Join(p.Opt, target))
			}
		}()
	}
	if !validReleaseTarget(target) {
		return errors.New("invalid target release")
	}
	if _, e = platform.Exec(ctx, filepath.Join(p.Opt, target, "nodekit"), "help"); e != nil {
		return e
	}
	config, e := serviceConfig(ctx, p)
	if e != nil {
		return e
	}
	if e = checkReleaseCompatibility(ctx, config, filepath.Join(p.Opt, target, "nodekit")); e != nil {
		return e
	}
	_ = p.admin(ctx, "POST", "/usage/flush", nil, nil)
	j := upgradeJournal{Old: old, New: target, Previous: previous, Phase: "prepared"}
	if e = writeJournal(p, j); e != nil {
		return e
	}
	restore := func(cause error) error {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		return errors.Join(cause, recoverUpgrade(recoveryCtx, p, false))
	}
	if e = services(ctx, "stop"); e != nil {
		return restore(e)
	}
	data, e := serviceTool(ctx, p, "snapshot")
	if e != nil {
		return restore(e)
	}
	if e = platform.WritePrivate(filepath.Join(lifecycleDir(p), "state.db"), data); e != nil {
		return restore(e)
	}
	j.Phase = "backed_up"
	if e = writeJournal(p, j); e != nil {
		return restore(e)
	}
	if e = switchLink(p.Opt, "previous", old); e != nil {
		return restore(e)
	}
	if e = switchLink(p.Opt, "current", target); e != nil {
		return restore(e)
	}
	j.Phase = "switched"
	if e = writeJournal(p, j); e != nil {
		return restore(e)
	}
	if _, e = serviceTool(ctx, p, "prepare"); e != nil {
		return restore(e)
	}
	if e = services(ctx, "start"); e != nil {
		return restore(e)
	}
	if e = waitReady(ctx, p); e != nil {
		return restore(e)
	}
	j.Phase = "committed"
	if e = writeJournal(p, j); e != nil {
		return restore(e)
	}
	if e = clearJournal(p); e != nil {
		return e
	}
	fmt.Fprintln(out, "已切换版本:", target)
	return pruneReleases(p)
}
func uninstall(ctx context.Context, p paths, purge bool, out io.Writer) error {
	if p.Root != "/" || os.Geteuid() != 0 {
		return errors.New("卸载需真实系统 root")
	}
	lock, e := operationLock(p)
	if e != nil {
		return e
	}
	defer lock.Close()
	m, e := loadHost(p)
	if errors.Is(e, os.ErrNotExist) {
		if err := owned(p.Opt); err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(p.Data, "state.db")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("database exists without ownership manifest; refusing removal")
		}
		link := filepath.Join(p.Root, "usr/local/bin/nodekit")
		if target, err := os.Readlink(link); err == nil && target == filepath.Join(p.Opt, "current/nodekit") {
			if err = os.Remove(link); err != nil {
				return err
			}
		}
		if purge {
			for _, dir := range []string{p.Etc, p.Data, p.Run} {
				if owned(dir) == nil {
					if err := os.RemoveAll(dir); err != nil {
						return err
					}
				}
			}
		}
		return os.RemoveAll(p.Opt)
	}
	if e != nil {
		return e
	}
	if e = verifyAccount(p, m); e != nil {
		return e
	}
	if e = checkOwnedFiles(m); e != nil {
		return e
	}
	for _, dir := range []string{p.Etc, p.Data, p.Opt} {
		if e = owned(dir); e != nil {
			return e
		}
	}
	var presentUnits []string
	for _, name := range []string{"nodekit-manager.service", "nodekit-core.service"} {
		if _, err := os.Stat(filepath.Join(p.Root, "etc/systemd/system", name)); err == nil {
			presentUnits = append(presentUnits, name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if _, err = platform.Exec(ctx, "systemctl", "is-active", "--quiet", name); err == nil {
			return errors.New("active unit has no owned file; refusing to stop it")
		}
	}
	if len(presentUnits) > 0 {
		if _, e = platform.Exec(ctx, append([]string{"systemctl", "disable", "--now"}, presentUnits...)...); e != nil {
			return e
		}
	}
	rules := m.Firewall
	if m.PendingFirewall != nil {
		rules = bindingsUnion(rules, bindingsUnion(m.PendingFirewall.Old, m.PendingFirewall.New))
	}
	if len(rules) > 0 {
		rt, err := p.runtime()
		if err != nil {
			return err
		}
		if rt.Firewall != "manual" {
			if e = (platform.Firewall{}).Remove(ctx, rules); e != nil {
				return e
			}
		}
	}
	for file := range m.Files {
		if e = os.Remove(file); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	link := filepath.Join(p.Root, "usr/local/bin/nodekit")
	if target, e := os.Readlink(link); e == nil && target == filepath.Join(p.Opt, "current/nodekit") {
		if e = os.Remove(link); e != nil {
			return e
		}
	}
	if _, e = platform.Exec(ctx, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	if e = owned(p.Run); e == nil {
		if e = os.RemoveAll(p.Run); e != nil {
			return e
		}
	}
	if purge {
		if e = os.RemoveAll(p.Data); e != nil {
			return e
		}
		if e = os.RemoveAll(p.Etc); e != nil {
			return e
		}
		if _, e = platform.Exec(ctx, "userdel", "nodekit"); e != nil {
			return e
		}
		_ = func() error { _, e := platform.Exec(ctx, "groupdel", "nodekit"); return e }()
	} else {
		m.Firewall = nil
		m.PendingFirewall = nil
		m.InitPhase = "retained"
		if e = saveHost(p, m); e != nil {
			return e
		}
	}
	fmt.Fprintln(out, "已卸载项目服务与程序；数据保留:", !purge)
	return os.RemoveAll(p.Opt)
}
