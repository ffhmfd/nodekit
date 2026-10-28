package cli

import (
	"context"
	"errors"
	"net/netip"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"syscall"
)

type purgeOps struct {
	DNS                                                       cloudflare.API
	Save                                                      func() error
	Stop, Firewall, Files, Data, Account, Credentials, Finish func(context.Context) error
}

type directoryIdentity struct {
	Device, Inode uint64
	UID, GID      uint32
}

func removePurgeData(p paths, m *hostManifest, save func() error) error {
	info, err := os.Lstat(p.Data)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid project data directory")
	}
	identity := directoryIdentity{uint64(st.Dev), st.Ino, st.Uid, st.Gid}
	if m.PurgeDataIdentity == nil {
		if err = owned(p.Data); err != nil {
			return err
		}
		m.PurgeDataIdentity = &identity
		// The root journal survives recursive removal of the in-tree marker.
		if err = save(); err != nil {
			return err
		}
	} else if *m.PurgeDataIdentity != identity {
		return errors.New("project data directory identity changed during purge")
	}
	return os.RemoveAll(p.Data)
}

// Credentials and the recovery entrypoint survive until remote DNS and owned
// host resources are removed. Each completed phase is persisted for retries.
func runPurge(ctx context.Context, m *hostManifest, ops purgeOps) error {
	if m.DNSOperation != nil {
		return errors.New("resolve the pending DNS operation before purge")
	}
	if m.PurgePhase == "" {
		m.PurgePhase = "prepared"
		if err := ops.Save(); err != nil {
			return err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var next string
		var action func(context.Context) error
		switch m.PurgePhase {
		case "prepared":
			for len(m.DNSRecords) > 0 {
				if ops.DNS == nil {
					return errors.New("DNS credentials required before deleting local files")
				}
				if err := cloudflare.DeleteManaged(ctx, ops.DNS, m.DNSRecords[0]); err != nil {
					return err
				}
				m.DNSRecords = m.DNSRecords[1:]
				if err := ops.Save(); err != nil {
					return err
				}
			}
			next = "dns_removed"
		case "dns_removed":
			action = ops.Stop
			next = "stopped"
		case "stopped":
			action = ops.Firewall
			next = "firewall_removed"
		case "firewall_removed":
			action = ops.Files
			next = "files_removed"
		case "files_removed":
			action = ops.Data
			next = "data_removed"
		case "data_removed":
			action = ops.Account
			next = "account_removed"
		case "account_removed":
			action = ops.Credentials
			next = "credentials_removed"
		case "credentials_removed":
			return ops.Finish(ctx)
		default:
			return errors.New("unknown purge recovery phase")
		}
		if action != nil {
			if err := action(ctx); err != nil {
				return err
			}
		}
		m.PurgePhase = next
		if err := ops.Save(); err != nil {
			return err
		}
	}
}

func removePurgeCredentials(p paths) error {
	for _, file := range []string{filepath.Join(p.Root, "root/nodekit-cloudflare.token"), filepath.Join(p.Etc, "cloudflare.token")} {
		// Unlink a substituted symlink, without following its target.
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// tmpfiles recreates the private runtime directory after reboot. Its fixed
// path, owner/group and mode prove ownership even when the marker disappeared.
// Call only after stopping the project services and before deleting the user.
func removePurgeRuntime(p paths, m hostManifest) error {
	info, err := os.Lstat(p.Run)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || info.Mode().Perm() != 0700 {
		return errors.New("runtime directory does not match the project account")
	}
	serviceOwned := int(st.Uid) == m.UID && int(st.Gid) == m.GID
	// Before preparePermissions completes, the root-owned installation journal
	// authenticates the claimed fixed runtime path. No marker is required on
	// retry because an interrupted recursive removal may already have removed it.
	initialRoot := st.Uid == 0 && st.Gid == 0 && (m.InitPhase == "prepared" || m.InitPhase == "configured")
	if !serviceOwned && !initialRoot {
		return errors.New("runtime directory does not match the project account")
	}
	return os.RemoveAll(p.Run)
}

func discoverLegacyDNS(ctx context.Context, api cloudflare.API, zone string, c model.Config) ([]cloudflare.ManagedRecord, error) {
	rows, err := api.Records(ctx, zone, c.Domain)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errors.New("legacy DNS is not uniquely identifiable; register it with nodekit dns adopt before purge")
	}
	r := rows[0]
	address, err := netip.ParseAddr(c.Address)
	if err != nil {
		return nil, err
	}
	actual, err := netip.ParseAddr(r.Content)
	if err != nil || actual.Unmap() != address.Unmap() || r.Name != c.Domain || (r.Type != "A" && r.Type != "AAAA") || r.Proxied != (c.EffectiveSubscriptionMode() == "cloudflare") {
		return nil, cloudflare.ErrConflict
	}
	return []cloudflare.ManagedRecord{{ZoneID: zone, Record: r, Previous: &r, Created: false}}, nil
}
