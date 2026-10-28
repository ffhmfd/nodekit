package model

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestNewCredentials(t *testing.T) {
	a, e := New()
	if e != nil {
		t.Fatal(e)
	}
	b, e := New()
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Validate(); e != nil {
		t.Fatal(e)
	}
	raw, e := base64.RawURLEncoding.DecodeString(a.Token)
	if e != nil || len(raw) < 32 {
		t.Fatal("weak subscription token")
	}
	if a.Token == b.Token || a.Reality.PrivateKey == b.Reality.PrivateKey {
		t.Fatal("credentials reused")
	}
	seen := map[string]bool{}
	for _, p := range a.Protocols {
		if seen[p.Password] {
			t.Fatal("password reused")
		}
		seen[p.Password] = true
		if p.Type == "ss" {
			k, e := base64.StdEncoding.DecodeString(p.Password)
			if e != nil || len(k) != 16 {
				t.Fatal("invalid SS2022 key")
			}
		}
	}
}
func TestInvalidConfig(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Domain = "bad\n.example" }, func(c *Config) { c.Protocols[0].Port = 443 }, func(c *Config) { c.Protocols[1].Port = c.Protocols[0].Port }, func(c *Config) { c.Quota = -1 }, func(c *Config) { c.ResetDay = 0 }, func(c *Config) { c.ResetHour = 24 }, func(c *Config) { c.Token = "short" }, func(c *Config) { c.Protocols[0].Type = "invalid" },
	} {
		c, _ := New()
		mutate(&c)
		if c.Validate() == nil {
			t.Fatalf("accepted invalid configuration %+v", c.Name)
		}
	}
}
func TestUnitsAndBeijingExpiry(t *testing.T) {
	for in, want := range map[string]int64{"1GB": 1000000000, "1GiB": 1073741824, "1TB": 1000000000000, "1TiB": 1099511627776, "1.5GB": 1500000000} {
		got, e := ParseBytes(in)
		if e != nil || got != want {
			t.Fatalf("%s: %d %v", in, got, e)
		}
	}
	for _, in := range []string{"-1GB", "1XB", "NaNGB", "99999999999999999999TB"} {
		if _, e := ParseBytes(in); e == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	got, e := ParseExpiry("2026-11-15 08:00")
	if e != nil || !got.Equal(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("bad expiry %v %v", got, e)
	}
}
