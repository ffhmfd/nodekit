package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type Firewall struct{ Run Runner }

func (f Firewall) backend(ctx context.Context) (string, error) {
	if f.Run == nil {
		f.Run = Exec
	}
	b, e := f.Run(ctx, "ufw", "status")
	if e == nil && strings.Contains(string(b), "Status: active") {
		return "ufw", nil
	}
	if _, e = f.Run(ctx, "iptables", "-S", "INPUT"); e == nil {
		return "iptables", nil
	}
	return "", errors.New("unsupported firewall layout; select manual mode and allow only project ports")
}
func (f Firewall) Apply(ctx context.Context, bindings []Binding) error {
	return f.change(ctx, bindings, false)
}
func (f Firewall) Remove(ctx context.Context, bindings []Binding) error {
	return f.change(ctx, bindings, true)
}
func (f Firewall) change(ctx context.Context, bindings []Binding, remove bool) error {
	if f.Run == nil {
		f.Run = Exec
	}
	backend, e := f.backend(ctx)
	if e != nil {
		return e
	}
	for _, b := range bindings {
		if (b.Network != "tcp" && b.Network != "udp") || b.Port < 1024 || b.Port > 65535 {
			return errors.New("invalid firewall binding")
		}
		tag := fmt.Sprintf("nodekit:%s:%d", b.Network, b.Port)
		if backend == "ufw" {
			status, e := f.Run(ctx, "ufw", "status")
			if e != nil {
				return e
			}
			owned := false
			for _, line := range strings.Split(string(status), "\n") {
				parts := strings.SplitN(line, "#", 2)
				if len(parts) == 2 && strings.TrimSpace(parts[1]) == tag {
					owned = true
					break
				}
			}
			if remove && !owned {
				continue
			}
			if !remove && owned {
				continue
			}
			args := []string{"ufw"}
			if remove {
				args = append(args, "--force", "delete")
			}
			args = append(args, "allow", "proto", b.Network, "from", "any", "to", "any", "port", fmt.Sprint(b.Port), "comment", tag)
			if _, e = f.Run(ctx, args...); e != nil {
				return fmt.Errorf("UFW project rule update failed: %w", e)
			}
			continue
		}
		tables := []string{"iptables"}
		if b.IPv6 {
			tables = append(tables, "ip6tables")
		}
		for _, tool := range tables {
			rule := []string{"-p", b.Network, "--dport", fmt.Sprint(b.Port), "-m", "comment", "--comment", tag, "-j", "ACCEPT"}
			check := append([]string{tool, "-C", "INPUT"}, rule...)
			_, present := f.Run(ctx, check...)
			if remove {
				if present != nil {
					continue
				}
				args := append([]string{tool, "-D", "INPUT"}, rule...)
				if _, e = f.Run(ctx, args...); e != nil {
					return e
				}
			} else if present != nil {
				args := append([]string{tool, "-I", "INPUT", "1"}, rule...)
				if _, e = f.Run(ctx, args...); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
