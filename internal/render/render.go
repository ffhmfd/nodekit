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
	for _, endpoint := range c.ListenerEndpoints() {
		n := endpoint.Protocol
		typ := n.Type
		if typ == "ss" {
			typ = "shadowsocks"
		}
		l := obj{"name": endpoint.Name, "type": typ, "listen": endpoint.Address, "port": n.Port}
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
	appendNode := func(n model.Protocol, name, address, family string) {
		names = append(names, name)
		v := obj{"name": name, "type": n.Type, "server": address, "port": n.Port, "udp": true}
		if c.IPv6Nodes != nil && family == "ipv4" {
			// A direct-mode domain may have AAAA records. Enabling client IPv6
			// must not silently turn an original IPv4 node into an IPv6 dial.
			v["ip-version"] = "ipv4"
		}
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
	for _, n := range c.Protocols {
		if n.Enabled {
			appendNode(n, c.NodeName(n), c.NodeAddress(), "ipv4")
		}
	}
	for _, n := range c.Protocols {
		if c.IPv6ProtocolEnabled(n.Type) {
			appendNode(n, c.IPv6NodeName(n), c.IPv6Nodes.Address, "ipv6")
		}
	}
	result := obj{"proxies": nodes}
	if !provider {
		for key, value := range clientRouting(c, names) {
			result[key] = value
		}
		result["dns"] = clientDNS(c.IPv6 || c.HasIPv6Nodes())
		result["sniffer"] = clientSniffer()
	}
	return yaml.Marshal(result)
}
