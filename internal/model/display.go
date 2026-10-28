package model

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

func ProtocolLabel(typ string) string {
	switch typ {
	case "vless":
		return "VLESS"
	case "ss":
		return "SS2022"
	case "tuic":
		return "TUIC"
	case "hysteria2":
		return "HY2"
	case "anytls":
		return "AnyTLS"
	}
	return typ
}

func CountryFlag(code string) string {
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return "🌐"
	}
	return string([]rune{0x1f1e6 + rune(code[0]-'A'), 0x1f1e6 + rune(code[1]-'A')})
}

func (c Config) NodeName(p Protocol) string {
	if p.Name != "" {
		return p.Name
	}
	if c.DisplayMode == "flag-host" {
		return fmt.Sprintf("%s %s · %s", CountryFlag(c.CountryCode), c.Name, ProtocolLabel(p.Type))
	}
	return c.Name + "-" + p.Type
}

func validDisplay(s string) bool {
	if strings.TrimSpace(s) == "" || len(s) > 256 {
		return false
	}
	return strings.IndexFunc(s, unicode.IsControl) < 0
}

func (c Config) validateDisplay() error {
	if !validDisplay(c.Name) {
		return errors.New("invalid display prefix")
	}
	if c.DisplayMode != "" && c.DisplayMode != "legacy" && c.DisplayMode != "flag-host" {
		return errors.New("display mode must be legacy or flag-host")
	}
	if c.CountryCode != "" && CountryFlag(c.CountryCode) == "🌐" {
		return errors.New("country must be a two-letter uppercase code or empty")
	}
	names := map[string]bool{"节点选择": true, "自动选择": true, "故障切换": true, "DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}
	for _, p := range c.Protocols {
		name := c.NodeName(p)
		if !validDisplay(name) || names[name] {
			return errors.New("invalid, duplicate or reserved node name")
		}
		names[name] = true
	}
	return nil
}

func (c *Config) SetDisplayDefaults(hostname, country string) error {
	next := c.Clone()
	next.DisplayMode = "flag-host"
	next.Name = strings.TrimSpace(hostname)
	next.CountryCode = strings.ToUpper(strings.TrimSpace(country))
	if err := next.Validate(); err != nil {
		return err
	}
	*c = next
	return nil
}

func ValidateRealityTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || (net.ParseIP(host) == nil && !ValidDomain(host)) {
		return errors.New("invalid REALITY target host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid REALITY target port")
	}
	return nil
}

func (c *Config) SetRealityServerName(name string) error {
	next := c.Clone()
	next.Reality.ServerName = strings.ToLower(strings.TrimSpace(name))
	next.Reality.Target = net.JoinHostPort(next.Reality.ServerName, "443")
	if err := next.Validate(); err != nil {
		return err
	}
	*c = next
	return nil
}
