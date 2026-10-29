package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"nodekit/internal/model"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

type Runner func(context.Context, ...string) ([]byte, error)

func Exec(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("empty command")
	}
	return exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
}

type Host struct{ OS, Version, Arch string }

func Probe(ctx context.Context) (Host, error) {
	b, e := os.ReadFile("/etc/os-release")
	if e != nil {
		return Host{}, e
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.SplitN(line, "=", 2)
		if len(p) == 2 {
			m[p[0]] = strings.Trim(p[1], `"`)
		}
	}
	h := Host{m["ID"], m["VERSION_ID"], runtime.GOARCH}
	if h.Arch != "amd64" && h.Arch != "arm64" {
		return h, errors.New("supported architectures: amd64/arm64")
	}
	if !(h.OS == "debian" && (h.Version == "12" || h.Version == "13") || h.OS == "ubuntu" && (h.Version == "22.04" || h.Version == "24.04")) {
		return h, errors.New("supported systems: Debian 12/13, Ubuntu 22.04/24.04")
	}
	if _, e = os.Stat("/run/systemd/system"); e != nil {
		return h, errors.New("systemd is required")
	}
	return h, nil
}
func Claim(dir string) error {
	info, e := os.Lstat(dir)
	if e == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing non-directory project path")
		}
		if Owned(dir) == nil {
			return nil
		}
		entries, e := os.ReadDir(dir)
		if e != nil {
			return e
		}
		if len(entries) > 0 {
			return fmt.Errorf("refusing to claim existing directory: %s", dir)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	marker, e := root.OpenFile(".nodekit-owned", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer marker.Close()
	if _, e = marker.Write([]byte("nodekit-v1\n")); e != nil {
		return e
	}
	return marker.Sync()
}

type Binding struct {
	Network string `json:"network"`
	Port    int    `json:"port"`
	IPv6    bool   `json:"ipv6"`
	Family  string `json:"family,omitempty"`
	Address string `json:"address,omitempty"`
}

func Bindings(c model.Config) []Binding {
	b := []Binding{{Network: "tcp", Port: c.SubscriptionPort, IPv6: c.IPv6}}
	seen := map[Binding]bool{b[0]: true}
	for _, endpoint := range c.ListenerEndpoints() {
		p := endpoint.Protocol
		networks := []string{"tcp"}
		switch p.Type {
		case "ss":
			networks = []string{"tcp", "udp"}
		case "tuic", "hysteria2":
			networks = []string{"udp"}
		}
		for _, network := range networks {
			v := Binding{Network: network, Port: p.Port, Family: endpoint.Family, Address: endpoint.Address}
			if endpoint.Family == "legacy" {
				v.Family, v.Address, v.IPv6 = "", "", c.IPv6
			}
			if !seen[v] {
				b = append(b, v)
				seen[v] = true
			}
		}
	}
	return b
}
func CheckPorts(c model.Config, previous []Binding) error {
	return checkPorts(c, previous, func(network, address string) error {
		if strings.HasPrefix(network, "tcp") {
			l, err := net.Listen(network, address)
			if err != nil {
				return err
			}
			return l.Close()
		}
		l, err := net.ListenPacket(network, address)
		if err != nil {
			return err
		}
		return l.Close()
	})
}

func (b Binding) validate() error {
	if (b.Network != "tcp" && b.Network != "udp") || b.Port < 1024 || b.Port > 65535 {
		return errors.New("invalid firewall binding")
	}
	if b.Family != "" && b.Family != "ipv4" && b.Family != "ipv6" || b.Family != "" && b.IPv6 {
		return errors.New("invalid binding family or contradictory legacy IPv6 flag")
	}
	if b.Address != "" {
		ip, err := netip.ParseAddr(b.Address)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || b.Family == "" || (b.Family == "ipv4") != ip.Is4() {
			return errors.New("binding address does not match family")
		}
	}
	return nil
}

func expandBindings(bindings []Binding) []Binding {
	var out []Binding
	seen := map[Binding]bool{}
	for _, b := range bindings {
		families := []string{b.Family}
		if b.Family == "" {
			families = []string{"ipv4"}
			if b.IPv6 {
				families = append(families, "ipv6")
			}
		}
		for _, family := range families {
			v := b
			v.Family, v.IPv6 = family, false
			if !seen[v] {
				out = append(out, v)
				seen[v] = true
			}
		}
	}
	return out
}

// CoverageDifference is logical socket coverage, not a safe firewall deletion
// plan. In particular a UFW legacy generic binding can physically own both
// families even when its old IPv6 flag is false. Use Reconcile for transitions.
func CoverageDifference(a, b []Binding) []Binding {
	var out []Binding
	for _, v := range expandBindings(a) {
		covered := false
		for _, old := range expandBindings(b) {
			if old.Network == v.Network && old.Port == v.Port && old.Family == v.Family && (old.Address == "" || old.Address == v.Address) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, v)
		}
	}
	return out
}

func checkPorts(c model.Config, previous []Binding, probe func(string, string) error) error {
	if e := c.Validate(); e != nil {
		return e
	}
	for _, b := range previous {
		if err := b.validate(); err != nil {
			return err
		}
	}
	for _, b := range CoverageDifference(Bindings(c), previous) {
		migration := false
		// Mihomo's legacy wildcard can occupy both families. Do not try to
		// rebind it while the old core is running; final core health remains
		// mandatory. The subscription socket is not a Mihomo listener.
		for _, old := range previous {
			if old.Family == "" && old.Network == b.Network && old.Port == b.Port && b.Port != c.SubscriptionPort {
				migration = true
				break
			}
		}
		if migration {
			continue
		}
		address, suffix := b.Address, "4"
		if b.Family == "ipv6" {
			suffix = "6"
			if address == "" {
				address = "::"
			}
		} else if address == "" {
			address = "0.0.0.0"
		}
		if err := probe(b.Network+suffix, net.JoinHostPort(address, fmt.Sprint(b.Port))); err != nil {
			return fmt.Errorf("port occupied %s%s/%d at %s: %w", b.Network, suffix, b.Port, address, err)
		}
	}
	return nil
}
