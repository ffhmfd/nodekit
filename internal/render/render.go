package render

import (
	"gopkg.in/yaml.v3"
	"nodekit/internal/model"
	"path/filepath"
)

type Paths struct{ Socket, WorkDir, Certificate, PrivateKey string }
type obj = map[string]any

func Server(c model.Config, p Paths) ([]byte, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	listeners := []obj{}
	if c.CertID != "" {
		p.Certificate = filepath.Join(p.WorkDir, "certs", c.CertID, "cert.pem")
		p.PrivateKey = filepath.Join(p.WorkDir, "certs", c.CertID, "key.pem")
	}
	listen := "0.0.0.0"
	if c.IPv6 {
		listen = "::"
	}
	for _, n := range c.Protocols {
		if !n.Enabled {
			continue
		}
		typ := n.Type
		if typ == "ss" {
			typ = "shadowsocks"
		}
		l := obj{"name": "nodekit-" + n.Type, "type": typ, "listen": listen, "port": n.Port}
		switch n.Type {
		case "vless":
			l["users"] = []obj{{"username": "personal", "uuid": n.UUID, "flow": "xtls-rprx-vision"}}
			l["reality-config"] = obj{"dest": c.Reality.Target, "private-key": c.Reality.PrivateKey, "short-id": []string{c.Reality.ShortID}, "server-names": []string{c.Reality.ServerName}}
		case "ss":
			l["cipher"] = "2022-blake3-aes-128-gcm"
			l["password"] = n.Password
			l["udp"] = true
		default:
			l["certificate"] = p.Certificate
			l["private-key"] = p.PrivateKey
			if n.Type == "tuic" {
				l["users"] = obj{n.UUID: n.Password}
				l["alpn"] = []string{"h3"}
				l["congestion-controller"] = "bbr"
			} else {
				l["users"] = obj{"personal": n.Password}
			}
		}
		listeners = append(listeners, l)
	}
	return yaml.Marshal(obj{"mode": "rule", "log-level": "warning", "ipv6": c.IPv6, "external-controller-unix": p.Socket, "listeners": listeners, "rules": []string{"MATCH,DIRECT"}})
}
func Subscription(c model.Config, provider bool) ([]byte, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	nodes := []obj{}
	names := []string{}
	for _, n := range c.Protocols {
		if !n.Enabled {
			continue
		}
		name := c.NodeName(n)
		names = append(names, name)
		v := obj{"name": name, "type": n.Type, "server": c.NodeAddress(), "port": n.Port, "udp": true}
		switch n.Type {
		case "vless":
			v["uuid"] = n.UUID
			v["flow"] = "xtls-rprx-vision"
			v["tls"] = true
			v["network"] = "tcp"
			v["servername"] = c.Reality.ServerName
			v["client-fingerprint"] = "chrome"
			v["reality-opts"] = obj{"public-key": c.Reality.PublicKey, "short-id": c.Reality.ShortID}
		case "ss":
			v["cipher"] = "2022-blake3-aes-128-gcm"
			v["password"] = n.Password
		case "tuic":
			v["uuid"] = n.UUID
			v["password"] = n.Password
			v["sni"] = c.Domain
			v["alpn"] = []string{"h3"}
			v["congestion-controller"] = "bbr"
			v["skip-cert-verify"] = false
		default:
			v["password"] = n.Password
			v["sni"] = c.Domain
			v["skip-cert-verify"] = false
		}
		nodes = append(nodes, v)
	}
	result := obj{"proxies": nodes}
	if !provider {
		choices := append([]string{}, names...)
		if len(choices) == 0 {
			choices = []string{"REJECT"}
		}
		result["mode"] = "rule"
		result["ipv6"] = c.IPv6
		result["proxy-groups"] = []obj{{"name": "节点选择", "type": "select", "proxies": append([]string{"自动选择", "故障切换"}, choices...)}, {"name": "自动选择", "type": "url-test", "proxies": choices, "url": "https://www.gstatic.com/generate_204", "interval": 300}, {"name": "故障切换", "type": "fallback", "proxies": choices, "url": "https://www.gstatic.com/generate_204", "interval": 300}}
		result["rules"] = []string{"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve", "IP-CIDR6,::1/128,DIRECT,no-resolve", "IP-CIDR6,fc00::/7,DIRECT,no-resolve", "IP-CIDR6,fe80::/10,DIRECT,no-resolve", "MATCH,节点选择"}
		result["dns"] = obj{"enable": true, "ipv6": c.IPv6, "nameserver": []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}}
	}
	return yaml.Marshal(result)
}
