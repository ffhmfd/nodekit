package render

import (
	"strconv"
	"strings"

	"nodekit/internal/model"
)

func clientRouting(c model.Config, names []string) obj {
	choices := append([]string{}, names...)
	if len(choices) == 0 {
		choices = []string{"REJECT"}
	}
	used := map[string]bool{"节点选择": true, "自动选择": true, "故障切换": true, "DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}
	for _, name := range names {
		used[name] = true
	}
	youtube := uniqueGroupName("▶️ YouTube", used)
	telegram := uniqueGroupName("📲 电报信息", used)
	ai := uniqueGroupName("🤖 ChatGPT", used)
	block := uniqueGroupName("🛑 全球拦截", used)
	final := uniqueGroupName("🐟 漏网之鱼", used)

	groups := []obj{
		{"name": "节点选择", "type": "select", "proxies": append(append([]string{"自动选择", "故障切换"}, choices...), "DIRECT")},
		{"name": "自动选择", "type": "url-test", "proxies": choices, "url": "https://www.gstatic.com/generate_204", "interval": 300},
		{"name": "故障切换", "type": "fallback", "proxies": choices, "url": "https://www.gstatic.com/generate_204", "interval": 300},
		{"name": youtube, "type": "select", "proxies": append([]string{"节点选择", "自动选择"}, choices...)},
		{"name": telegram, "type": "select", "proxies": append([]string{"节点选择"}, choices...)},
		{"name": ai, "type": "select", "proxies": aiNodeNames(c, names)},
		{"name": block, "type": "select", "proxies": []string{"REJECT", "DIRECT"}},
		{"name": final, "type": "select", "proxies": append([]string{"节点选择", "DIRECT", "自动选择"}, choices...)},
	}
	rules := []string{
		"GEOSITE,youtube," + youtube,
		"OR,((DOMAIN,gemini.google.com),(DOMAIN,bard.google.com),(GEOSITE,openai))," + ai,
		"RULE-SET,applications,DIRECT",
		"DOMAIN,clash.razord.top,DIRECT",
		"DOMAIN,yacd.haishan.me,DIRECT",
		"RULE-SET,private,DIRECT",
		"RULE-SET,reject," + block,
		"RULE-SET,icloud,节点选择",
		"RULE-SET,apple,节点选择",
		"RULE-SET,google,节点选择",
		"RULE-SET,proxy,节点选择",
		"RULE-SET,direct,DIRECT",
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
		"IP-CIDR6,::1/128,DIRECT,no-resolve",
		"IP-CIDR6,fc00::/7,DIRECT,no-resolve",
		"IP-CIDR6,fe80::/10,DIRECT,no-resolve",
		"RULE-SET,lancidr,DIRECT",
		"RULE-SET,cncidr,DIRECT",
		"RULE-SET,telegramcidr," + telegram,
		"GEOIP,LAN,DIRECT",
		"GEOIP,CN,DIRECT",
		"MATCH," + final,
	}
	providers := obj{}
	for _, name := range []string{"reject", "icloud", "apple", "google", "proxy", "direct", "private", "telegramcidr", "cncidr", "lancidr", "applications"} {
		behavior := "domain"
		switch name {
		case "telegramcidr", "cncidr", "lancidr":
			behavior = "ipcidr"
		case "applications":
			behavior = "classical"
		}
		providers[name] = obj{
			"type": "http", "behavior": behavior, "interval": 86400,
			"url":  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/" + name + ".txt",
			"path": "./ruleset/" + name + ".yaml",
		}
	}
	return obj{"mode": "rule", "ipv6": c.IPv6 || c.HasIPv6Nodes(), "proxy-groups": groups, "rules": rules, "rule-providers": providers}
}

func uniqueGroupName(base string, used map[string]bool) string {
	name := base
	for suffix := 1; used[name]; suffix++ {
		name = base + " · NodeKit"
		if suffix > 1 {
			name += " " + strconv.Itoa(suffix)
		}
	}
	used[name] = true
	return name
}

func aiNodeNames(c model.Config, names []string) []string {
	eligible := []string{}
	if !strings.EqualFold(c.CountryCode, "HK") {
		for _, name := range names {
			lower := strings.ToLower(name)
			if strings.Contains(lower, "🇭🇰") || strings.Contains(lower, "港") || strings.Contains(lower, "hk") || strings.Contains(lower, "hongkong") {
				continue
			}
			eligible = append(eligible, name)
		}
	}
	if len(eligible) == 0 {
		return []string{"REJECT"}
	}
	return eligible
}
