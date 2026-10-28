package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"nodekit/internal/model"
	"strings"
	"time"
)

func probeReality(ctx context.Context, r model.Reality) error {
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: r.ServerName, NextProtos: []string{"h2"}}}
	conn, err := dialer.DialContext(probe, "tcp", r.Target)
	if err != nil {
		return errors.New("REALITY target TLS 1.3 verification failed; configuration retained")
	}
	defer conn.Close()
	if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != "h2" {
		return errors.New("REALITY target must support h2")
	}
	return nil
}

func applyAdvancedSetting(ctx context.Context, c *model.Config, key, value string, probe func(context.Context, model.Reality) error) error {
	next := c.Clone()
	switch key {
	case "country":
		next.CountryCode = strings.ToUpper(strings.TrimSpace(value))
		if value == "auto" {
			next.CountryCode = ""
		}
	case "name-style":
		next.DisplayMode = value
	case "reality-sni":
		if err := next.SetRealityServerName(value); err != nil {
			return err
		}
	case "reality-target":
		next.Reality.Target = value
	default:
		return errors.New("unknown advanced setting")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if key == "reality-sni" || key == "reality-target" {
		if probe == nil {
			probe = probeReality
		}
		if err := probe(ctx, next.Reality); err != nil {
			return err
		}
	}
	*c = next
	return nil
}
