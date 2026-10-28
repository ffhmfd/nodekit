package cli

import (
	"context"
	"encoding/json"
	"errors"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type capabilities struct {
	SubscriptionModes []string `json:"subscription_modes"`
	Features          []string `json:"features"`
}

func checkReleaseCompatibility(ctx context.Context, c model.Config, binary string, extra ...string) error {
	required := map[string]bool{}
	for _, feature := range extra {
		required[feature] = true
	}
	if c.DisplayMode != "" || c.CountryCode != "" {
		required["node-names-v1"] = true
	}
	for _, p := range c.Protocols {
		if p.Name != "" {
			required["node-names-v1"] = true
		}
	}
	if c.ManagedDNS {
		required["managed-dns-v1"] = true
		required["purge-v1"] = true
	}
	if c.EffectiveSubscriptionMode() == "direct" && len(required) == 0 {
		return nil
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(probe, binary, "capabilities").Output()
	var result capabilities
	if err == nil && json.Unmarshal(data, &result) == nil {
		modeOK := false
		for _, mode := range result.SubscriptionModes {
			if mode == c.EffectiveSubscriptionMode() {
				modeOK = true
			}
		}
		if modeOK {
			for _, feature := range result.Features {
				delete(required, feature)
			}
			if len(required) == 0 {
				return nil
			}
			return errors.New("目标程序不支持现有DNS/名称/卸载状态，拒绝降级")
		}
	}
	return errors.New("目标程序不支持当前订阅模式；如需降级，请先显式切回 direct")
}

func hostFeatures(m hostManifest) []string {
	out := append([]string(nil), m.RequiredFeatures...)
	if len(m.DNSRecords) > 0 || m.DNSOperation != nil || m.InstallationID != "" || m.PurgePhase != "" {
		out = append(out, "managed-dns-v1", "purge-v1")
	}
	return out
}

func serviceBinary(ctx context.Context, p paths, c model.Config) (string, error) {
	m, err := loadHost(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	for _, name := range []string{"current", "previous"} {
		binary := filepath.Join(p.Opt, name, "nodekit")
		if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() {
			continue
		}
		if checkReleaseCompatibility(ctx, c, binary, hostFeatures(m)...) == nil {
			return binary, nil
		}
	}
	return "", errors.New("no compatible service recovery helper available")
}

func saveRetainedRequirements(p paths, m *hostManifest, c model.Config) error {
	features := map[string]bool{}
	for _, f := range hostFeatures(*m) {
		features[f] = true
	}
	if c.DisplayMode != "" || c.CountryCode != "" {
		features["node-names-v1"] = true
	}
	for _, v := range c.Protocols {
		if v.Name != "" {
			features["node-names-v1"] = true
		}
	}
	if c.ManagedDNS {
		features["managed-dns-v1"] = true
		features["purge-v1"] = true
	}
	m.RequiredFeatures = nil
	for f := range features {
		m.RequiredFeatures = append(m.RequiredFeatures, f)
	}
	sort.Strings(m.RequiredFeatures)
	m.RetainedMode = c.EffectiveSubscriptionMode()
	if err := saveHost(p, *m); err != nil {
		return err
	}
	return platform.WritePrivate(filepath.Join(p.Etc, "required-features"), []byte("mode="+m.RetainedMode+"\n"+strings.Join(m.RequiredFeatures, "\n")+"\n"))
}

func checkRetainedCompatibility(ctx context.Context, p paths, binary string) error {
	m, err := loadHost(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if m.PurgePhase != "" || m.DNSOperation != nil {
		return errors.New("finish pending DNS/purge recovery using the installed manager before reinstalling")
	}
	features := hostFeatures(m)
	mode := m.RetainedMode
	b, err := platform.ReadPrivate(filepath.Join(p.Etc, "required-features"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "mode=") {
				mode = strings.TrimPrefix(line, "mode=")
			} else if line != "" {
				features = append(features, line)
			}
		}
	}
	return checkReleaseCompatibility(ctx, model.Config{SubscriptionMode: mode}, binary, features...)
}
