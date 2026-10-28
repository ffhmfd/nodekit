package model

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata"
)

type Protocol struct {
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	UUID     string `json:"uuid"`
}
type Reality struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	ServerName string `json:"server_name"`
	Target     string `json:"target"`
}
type Config struct {
	Schema           int        `json:"schema"`
	Revision         int64      `json:"revision"`
	Name             string     `json:"name"`
	Domain           string     `json:"domain"`
	Address          string     `json:"address"`
	IPv6             bool       `json:"ipv6"`
	Protocols        []Protocol `json:"protocols"`
	SubscriptionPort int        `json:"subscription_port"`
	Quota            int64      `json:"quota"`
	Expiry           *time.Time `json:"expiry,omitempty"`
	ResetDay         int        `json:"reset_day"`
	ResetHour        int        `json:"reset_hour"`
	Token            string     `json:"token"`
	Reality          Reality    `json:"reality"`
	CertID           string     `json:"cert_id,omitempty"`
}

func (c Config) Clone() Config {
	out := c
	out.Protocols = append([]Protocol(nil), c.Protocols...)
	if c.Expiry != nil {
		expiry := *c.Expiry
		out.Expiry = &expiry
	}
	return out
}

func RandomToken() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func New() (Config, error) {
	c := Config{Schema: 1, Revision: 1, Name: "NodeKit", Domain: "node.example.com", Address: "127.0.0.1", SubscriptionPort: 24446, ResetDay: 1, ResetHour: 0}
	var e error
	c.Token, e = RandomToken()
	if e != nil {
		return c, e
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return c, e
	}
	short := make([]byte, 8)
	if _, e = rand.Read(short); e != nil {
		return c, e
	}
	c.Reality = Reality{base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), hex.EncodeToString(short), "www.microsoft.com", "www.microsoft.com:443"}
	for i, typ := range []string{"vless", "ss", "tuic", "hysteria2", "anytls"} {
		b := make([]byte, 16)
		if _, e = rand.Read(b); e != nil {
			return c, e
		}
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		id := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
		password, e := RandomToken()
		if e != nil {
			return c, e
		}
		if typ == "ss" {
			b = make([]byte, 16)
			if _, e = rand.Read(b); e != nil {
				return c, e
			}
			password = base64.StdEncoding.EncodeToString(b)
		}
		c.Protocols = append(c.Protocols, Protocol{typ, true, 24441 + i, password, id})
	}
	return c, nil
}

var domainRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$`)
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func ValidDomain(s string) bool { return len(s) <= 253 && domainRE.MatchString(s) }
func (c Config) Validate() error {
	if c.Schema != 1 || c.Revision < 1 {
		return errors.New("unsupported schema/revision")
	}
	if c.CertID != "" {
		raw, e := hex.DecodeString(c.CertID)
		if e != nil || len(raw) != 32 {
			return errors.New("invalid certificate ID")
		}
	}
	if strings.TrimSpace(c.Name) == "" || len(c.Name) > 128 || strings.ContainsAny(c.Name, "\r\n\x00") {
		return errors.New("invalid name")
	}
	if !ValidDomain(c.Domain) {
		return errors.New("invalid domain")
	}
	if c.Address != "" && net.ParseIP(c.Address) == nil {
		return errors.New("address must be an IP")
	}
	if c.Quota < 0 || c.ResetDay < 1 || c.ResetDay > 31 || c.ResetHour < 0 || c.ResetHour > 23 {
		return errors.New("invalid quota/reset time")
	}
	b, e := base64.RawURLEncoding.DecodeString(c.Token)
	if e != nil || len(b) < 32 {
		return errors.New("invalid subscription token")
	}
	ports := map[int]bool{}
	add := func(p int) error {
		if p < 1024 || p > 65535 || ports[p] {
			return errors.New("invalid or duplicate port")
		}
		ports[p] = true
		return nil
	}
	if e = add(c.SubscriptionPort); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, p := range c.Protocols {
		if seen[p.Type] {
			return errors.New("duplicate protocol")
		}
		seen[p.Type] = true
		switch p.Type {
		case "vless", "ss", "tuic", "hysteria2", "anytls":
		default:
			return errors.New("unknown protocol")
		}
		if e = add(p.Port); e != nil {
			return e
		}
		if len(p.Password) < 16 {
			return errors.New("password too short")
		}
		if p.Type == "vless" || p.Type == "tuic" {
			if !uuidRE.MatchString(p.UUID) {
				return errors.New("invalid UUID")
			}
		}
		if p.Type == "ss" {
			k, e := base64.StdEncoding.DecodeString(p.Password)
			if e != nil || len(k) != 16 {
				return errors.New("invalid SS2022 key")
			}
		}
	}
	key, e := base64.RawURLEncoding.DecodeString(c.Reality.PrivateKey)
	if e != nil {
		return errors.New("invalid REALITY key")
	}
	priv, e := ecdh.X25519().NewPrivateKey(key)
	if e != nil || base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()) != c.Reality.PublicKey {
		return errors.New("REALITY key mismatch")
	}
	id, e := hex.DecodeString(c.Reality.ShortID)
	if e != nil || len(id) == 0 || len(id) > 8 {
		return errors.New("invalid REALITY short ID")
	}
	if !ValidDomain(c.Reality.ServerName) {
		return errors.New("invalid REALITY SNI")
	}
	host, port, e := net.SplitHostPort(c.Reality.Target)
	if e != nil || host == "" || port == "" {
		return errors.New("invalid REALITY target")
	}
	return nil
}
func ParseBytes(s string) (int64, error) {
	units := map[string]int64{"GB": 1000000000, "TB": 1000000000000, "GiB": 1073741824, "TiB": 1099511627776}
	for suffix, mult := range units {
		if strings.HasSuffix(s, suffix) {
			v, ok := new(big.Rat).SetString(strings.TrimSpace(strings.TrimSuffix(s, suffix)))
			if !ok || v.Sign() < 0 {
				return 0, errors.New("invalid quota")
			}
			v.Mul(v, new(big.Rat).SetInt64(mult))
			if !v.IsInt() || !v.Num().IsInt64() {
				return 0, errors.New("quota overflow or fractional byte")
			}
			return v.Num().Int64(), nil
		}
	}
	return 0, errors.New("use GB/TB/GiB/TiB")
}
func ParseExpiry(s string) (time.Time, error) {
	loc, e := time.LoadLocation("Asia/Shanghai")
	if e != nil {
		return time.Time{}, e
	}
	t, e := time.ParseInLocation("2006-01-02 15:04", s, loc)
	return t.UTC(), e
}
