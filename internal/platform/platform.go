package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
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
}

func Bindings(c model.Config) []Binding {
	b := []Binding{{"tcp", c.SubscriptionPort, c.IPv6}}
	for _, p := range c.Protocols {
		if !p.Enabled {
			continue
		}
		switch p.Type {
		case "ss":
			b = append(b, Binding{"tcp", p.Port, c.IPv6}, Binding{"udp", p.Port, c.IPv6})
		case "tuic", "hysteria2":
			b = append(b, Binding{"udp", p.Port, c.IPv6})
		default:
			b = append(b, Binding{"tcp", p.Port, c.IPv6})
		}
	}
	return b
}
func CheckPorts(c model.Config, previous []Binding) error {
	if e := c.Validate(); e != nil {
		return e
	}
	owned := map[Binding]bool{}
	for _, b := range previous {
		owned[b] = true
	}
	for _, b := range Bindings(c) {
		if owned[b] {
			continue
		}
		addr := fmt.Sprintf("0.0.0.0:%d", b.Port)
		if b.Network == "tcp" {
			l, e := net.Listen("tcp4", addr)
			if e != nil {
				return fmt.Errorf("port occupied tcp/%d: %w", b.Port, e)
			}
			l.Close()
		} else {
			l, e := net.ListenPacket("udp4", addr)
			if e != nil {
				return fmt.Errorf("port occupied udp/%d: %w", b.Port, e)
			}
			l.Close()
		}
		if b.IPv6 {
			addr = fmt.Sprintf("[::]:%d", b.Port)
			if b.Network == "tcp" {
				l, e := net.Listen("tcp6", addr)
				if e != nil {
					return e
				}
				l.Close()
			} else {
				l, e := net.ListenPacket("udp6", addr)
				if e != nil {
					return e
				}
				l.Close()
			}
		}
	}
	return nil
}
