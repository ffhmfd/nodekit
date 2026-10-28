package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"nodekit/internal/platform"
	"os"
	"path/filepath"
	"strings"
)

func installPackage(ctx context.Context, p paths, args []string, out io.Writer) error {
	if p.Root == "/" {
		if os.Geteuid() != 0 {
			return errors.New("安装需要 root")
		}
		if _, e := platform.Probe(ctx); e != nil {
			return e
		}
	}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(out)
	file := fs.String("file", "", "release archive")
	sha := fs.String("sha256", "", "trusted SHA256")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if e := platform.Claim(p.Opt); e != nil {
		return e
	}
	if e := os.Chmod(p.Opt, 0755); e != nil {
		return e
	}
	lock, lockErr := operationLock(p)
	if lockErr != nil {
		return lockErr
	}
	defer lock.Close()
	releases := filepath.Join(p.Opt, "releases")
	if e := os.MkdirAll(releases, 0755); e != nil {
		return e
	}
	if e := os.Chmod(releases, 0755); e != nil {
		return e
	}
	stage := filepath.Join(p.Opt, ".install-stage")
	if _, e := os.Lstat(stage); e == nil {
		return errors.New("unfinished install stage exists")
	}
	meta, e := platform.ExtractRelease(*file, stage, *sha)
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	if e = checkRetainedCompatibility(ctx, p, filepath.Join(stage, "nodekit")); e != nil {
		return e
	}
	target := "releases/" + meta.Version + "-" + (*sha)[:12]
	alreadyInstalled := false
	if old, e := os.Readlink(filepath.Join(p.Opt, "current")); e == nil {
		if old == target {
			alreadyInstalled = true
		} else {
			return errors.New("已有安装，请使用 upgrade")
		}
	}
	if !alreadyInstalled {
		if _, e := os.Lstat(filepath.Join(p.Opt, "current")); !errors.Is(e, os.ErrNotExist) {
			return errors.New("current 路径冲突")
		}
		if e = os.Chmod(stage, 0755); e != nil {
			return e
		}
		if e = os.Rename(stage, filepath.Join(p.Opt, target)); e != nil {
			return e
		}
		if e = switchLink(p.Opt, "current", target); e != nil {
			return e
		}
		if e = switchLink(p.Opt, "previous", target); e != nil {
			return e
		}
	}
	binDir := filepath.Join(p.Root, "usr/local/bin")
	if _, err := os.Lstat(filepath.Join(p.Opt, "previous")); errors.Is(err, os.ErrNotExist) {
		if e = switchLink(p.Opt, "previous", target); e != nil {
			return e
		}
	}
	if e = os.MkdirAll(binDir, 0755); e != nil {
		return e
	}
	if p.Root != "/" {
		if e = os.Chmod(binDir, 0755); e != nil {
			return e
		}
	}
	link := filepath.Join(binDir, "nodekit")
	dest := filepath.Join(p.Opt, "current/nodekit")
	if existing, e := os.Readlink(link); e == nil {
		if existing != dest {
			return errors.New("已有 nodekit 命令不是本项目")
		}
	} else if _, e := os.Lstat(link); !errors.Is(e, os.ErrNotExist) {
		return errors.New("已有 nodekit 命令不能覆盖")
	} else if e = os.Symlink(dest, link); e != nil {
		return e
	}
	fmt.Fprintln(out, "程序已安装。首次运行 nodekit init；保留数据重装运行 nodekit resume。")
	return nil
}
func resume(ctx context.Context, p paths) error {
	if p.Root != "/" || os.Geteuid() != 0 {
		return errors.New("resume 需要真实系统 root")
	}
	if e := owned(p.Data); e != nil {
		return e
	}
	if e := owned(p.Etc); e != nil {
		return e
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
	if m.PurgePhase != "" {
		return errors.New("purge is incomplete; resume uninstall --purge")
	}
	if e = verifyAccount(p, m); e != nil {
		return e
	}
	if e = checkOwnedFiles(m); e != nil {
		return e
	}
	if e = preparePermissions(p, m); e != nil {
		return e
	}
	if m.DNSOperation != nil {
		client, err := dnsClient(p)
		if err != nil {
			return err
		}
		if err = recoverDNS(ctx, p, &m, client); err != nil {
			return err
		}
	}
	c, e := serviceConfig(ctx, p)
	if e != nil {
		return e
	}
	m.Firewall = platform.Bindings(c)
	if e = saveHost(p, m); e != nil {
		return e
	}
	if _, e = serviceTool(ctx, p, "prepare"); e != nil {
		return e
	}
	if e = installUnits(ctx, p); e != nil {
		return e
	}
	if e = waitReady(ctx, p); e != nil {
		return e
	}
	m.InitPhase = "ready"
	return saveHost(p, m)
}
func pruneReleases(p paths) error {
	current, e := os.Readlink(filepath.Join(p.Opt, "current"))
	if e != nil {
		return e
	}
	previous, _ := os.Readlink(filepath.Join(p.Opt, "previous"))
	entries, e := os.ReadDir(filepath.Join(p.Opt, "releases"))
	if e != nil {
		return e
	}
	for _, entry := range entries {
		rel := "releases/" + entry.Name()
		if rel == current || rel == previous {
			continue
		}
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "v") {
			if e = os.RemoveAll(filepath.Join(p.Opt, rel)); e != nil {
				return e
			}
		}
	}
	return nil
}
