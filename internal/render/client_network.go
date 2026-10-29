package render

func clientDNS(ipv6 bool) obj {
	return obj{
		"enable":             true,
		"ipv6":               ipv6,
		"enhanced-mode":      "fake-ip",
		"fake-ip-range":      "198.18.0.1/16",
		"fake-ip-filter":     []string{"*", "+.lan", "+.local"},
		"use-hosts":          true,
		"default-nameserver": []string{"223.5.5.5", "1.12.12.12"},
		"nameserver":         []string{"tls://223.5.5.5:853", "tls://1.12.12.12:853"},
	}
}

func clientSniffer() obj {
	return obj{
		"enable":               true,
		"override-destination": true,
		"force-dns-mapping":    true,
		"parse-pure-ip":        true,
		"sniff": obj{
			"HTTP": obj{"ports": []any{80, "8080-8880"}, "override-destination": true},
			"TLS":  obj{"ports": []int{443, 8443}, "override-destination": true},
			"QUIC": obj{"ports": []int{443, 8443}, "override-destination": true},
		},
	}
}
