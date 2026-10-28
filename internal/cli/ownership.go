package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/packaging"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type firewallOperation struct {
	Old, New []platform.Binding
	Revision int64
}
type hostManifest struct {
	UID, GID        int
	Files           map[string]string
	Firewall        []platform.Binding
	PendingFirewall *firewallOperation
	InitPhase       string
}

func hashBytes(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func saveHost(p paths, m hostManifest) error {
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	return platform.WritePrivate(filepath.Join(p.Etc, "host.json"), b)
}
func loadHost(p paths) (hostManifest, error) {
	var m hostManifest
	b, e := platform.ReadPrivate(filepath.Join(p.Etc, "host.json"))
	if e != nil {
		return m, e
	}
	e = json.Unmarshal(b, &m)
	return m, e
}
func checkOwnedFiles(m hostManifest) error {
	for path, digest := range m.Files {
		info, e := os.Lstat(path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("owned file replaced: %s", path)
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if hashBytes(b) != digest {
			return fmt.Errorf("owned file modified or replaced: %s", path)
		}
	}
	return nil
}
func unitFiles(p paths) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, name := range []string{"nodekit-core.service", "nodekit-manager.service"} {
		b, e := packaging.Units.ReadFile(name)
		if e != nil {
			return nil, e
		}
		out[filepath.Join(p.Root, "etc/systemd/system", name)] = b
	}
	out[filepath.Join(p.Root, "etc/tmpfiles.d/nodekit.conf")] = []byte("d /run/nodekit 0700 nodekit nodekit -\n")
	return out, nil
}
func verifyAccount(p paths, m hostManifest) error {
	u, e := user.Lookup("nodekit")
	if e != nil {
		return e
	}
	g, e := user.LookupGroup("nodekit")
	if e != nil {
		return e
	}
	if u.Uid != strconv.Itoa(m.UID) || u.Gid != strconv.Itoa(m.GID) || g.Gid != strconv.Itoa(m.GID) || u.HomeDir != p.Data {
		return errors.New("nodekit account does not match owned identity")
	}
	return nil
}
func preflightHost(ctx context.Context, p paths) (hostManifest, error) {
	if m, e := loadHost(p); e == nil {
		if e = checkOwnedFiles(m); e != nil {
			return m, e
		}
		return ensureAccount(ctx, p, m)
	} else if !errors.Is(e, os.ErrNotExist) {
		return m, e
	}
	if _, e := user.Lookup("nodekit"); e == nil {
		return hostManifest{}, errors.New("refusing existing unowned nodekit user")
	}
	if _, e := user.LookupGroup("nodekit"); e == nil {
		return hostManifest{}, errors.New("refusing existing unowned nodekit group")
	}
	files, e := unitFiles(p)
	if e != nil {
		return hostManifest{}, e
	}
	m := hostManifest{UID: -1, GID: -1, Files: map[string]string{}, InitPhase: "prepared"}
	for path, b := range files {
		if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			return m, fmt.Errorf("refusing existing resource: %s", path)
		}
		m.Files[path] = hashBytes(b)
	}
	for _, name := range []string{"nodekit-core.service", "nodekit-manager.service"} {
		state, err := platform.Exec(ctx, "systemctl", "show", "--property=LoadState", "--value", name)
		if err != nil {
			return m, err
		}
		if strings.TrimSpace(string(state)) != "not-found" {
			return m, fmt.Errorf("refusing existing systemd unit: %s", name)
		}
	}
	for id := 999; id >= 900; id-- {
		_, ue := user.LookupId(strconv.Itoa(id))
		_, ge := user.LookupGroupId(strconv.Itoa(id))
		if ue != nil && ge != nil {
			m.UID = id
			m.GID = id
			break
		}
	}
	if m.UID < 0 {
		return m, errors.New("no free project system UID/GID in 900..999")
	}
	if e = saveHost(p, m); e != nil {
		return m, e
	}
	return ensureAccount(ctx, p, m)
}
func ensureAccount(ctx context.Context, p paths, m hostManifest) (hostManifest, error) {
	if m.UID < 900 || m.UID > 999 || m.GID != m.UID {
		return m, errors.New("invalid owned account identity")
	}
	if group, e := user.LookupGroup("nodekit"); e == nil {
		if group.Gid != strconv.Itoa(m.GID) {
			return m, errors.New("group identity changed")
		}
	} else {
		if _, e = platform.Exec(ctx, "groupadd", "--system", "--gid", strconv.Itoa(m.GID), "nodekit"); e != nil {
			return m, e
		}
	}
	if _, e := user.Lookup("nodekit"); e != nil {
		if _, e = platform.Exec(ctx, "useradd", "--system", "--uid", strconv.Itoa(m.UID), "--gid", strconv.Itoa(m.GID), "--home-dir", p.Data, "--shell", "/usr/sbin/nologin", "nodekit"); e != nil {
			return m, e
		}
	}
	return m, verifyAccount(p, m)
}
func bindingsUnion(a, b []platform.Binding) []platform.Binding {
	out := append([]platform.Binding(nil), a...)
	seen := map[platform.Binding]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func serviceConfig(ctx context.Context, p paths) (model.Config, error) {
	var c model.Config
	b, e := platform.Exec(ctx, "runuser", "-u", "nodekit", "--", filepath.Join(p.Opt, "current/nodekit"), "inspect")
	if e != nil {
		return c, errors.New("cannot inspect configuration as service identity")
	}
	e = json.Unmarshal(b, &c)
	if e != nil {
		return c, e
	}
	return c, c.Validate()
}

func preparePermissions(p paths, m hostManifest) error {
	if e := verifyAccount(p, m); e != nil {
		return e
	}
	if e := platform.Claim(p.Run); e != nil {
		return e
	}
	for _, dir := range []string{p.Data, p.Run} {
		if e := owned(dir); e != nil {
			return e
		}
		root, e := os.OpenRoot(dir)
		if e != nil {
			return e
		}
		e = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			return root.Chown(path, m.UID, m.GID)
		})
		root.Close()
		if e != nil {
			return e
		}
	}
	if e := os.Chown(p.Etc, 0, m.GID); e != nil {
		return e
	}
	if e := os.Chmod(p.Etc, 0750); e != nil {
		return e
	}
	root, e := os.OpenRoot(p.Etc)
	if e != nil {
		return e
	}
	defer root.Close()
	for _, name := range []string{"runtime.json", "cloudflare.token"} {
		info, e := root.Lstat(name)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("invalid service settings file")
		}
		if e = root.Chown(name, 0, m.GID); e != nil {
			return e
		}
		if e = root.Chmod(name, 0640); e != nil {
			return e
		}
	}
	return nil
}
