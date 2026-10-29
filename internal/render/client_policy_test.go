package render

import (
	"path"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"nodekit/internal/model"
)

func routingConfig(t *testing.T) model.Config {
	t.Helper()
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func routingDocument(t *testing.T, c model.Config, provider bool) obj {
	t.Helper()
	data, err := Subscription(c, provider)
	if err != nil {
		t.Fatal(err)
	}
	var doc obj
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func routingStrings(t *testing.T, raw any) []string {
	t.Helper()
	values, ok := raw.([]any)
	if !ok {
		t.Fatalf("want a string list, got %T", raw)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		s, ok := value.(string)
		if !ok {
			t.Fatalf("want a string, got %T", value)
		}
		result = append(result, s)
	}
	return result
}

func routingGroups(t *testing.T, doc obj) map[string]obj {
	t.Helper()
	groups := map[string]obj{}
	for _, raw := range doc["proxy-groups"].([]any) {
		group := raw.(obj)
		name := group["name"].(string)
		if _, duplicate := groups[name]; duplicate {
			t.Fatalf("duplicate group %q", name)
		}
		groups[name] = group
	}
	return groups
}

func routingChoices(t *testing.T, groups map[string]obj, name string) []string {
	t.Helper()
	group, ok := groups[name]
	if !ok {
		t.Fatalf("missing policy group %q", name)
	}
	return routingStrings(t, group["proxies"])
}

func assertRoutingGraph(t *testing.T, doc obj, aiGroup string) {
	t.Helper()
	nodes := map[string]bool{}
	for _, raw := range doc["proxies"].([]any) {
		name := raw.(obj)["name"].(string)
		if nodes[name] {
			t.Fatalf("duplicate node %q", name)
		}
		nodes[name] = true
	}
	groups := routingGroups(t, doc)
	builtins := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}
	resolves := func(name string) bool {
		_, isGroup := groups[name]
		return nodes[name] || isGroup || builtins[name]
	}
	for name, group := range groups {
		if nodes[name] || builtins[name] {
			t.Fatalf("group %q shadows a node or built-in", name)
		}
		refs := routingStrings(t, group["proxies"])
		if len(refs) == 0 {
			t.Fatalf("group %q has unsafe empty candidates", name)
		}
		for _, ref := range refs {
			if !resolves(ref) {
				t.Fatalf("group %q has unresolved target %q", name, ref)
			}
			if name == aiGroup && !nodes[ref] && ref != "REJECT" {
				t.Fatalf("AI group must not escape through %q", ref)
			}
		}
	}
	for _, rule := range routingStrings(t, doc["rules"]) {
		parts := strings.Split(rule, ",")
		target := parts[len(parts)-1]
		if target == "no-resolve" {
			target = parts[len(parts)-2]
		}
		if !resolves(target) {
			t.Fatalf("rule %q has unresolved target %q", rule, target)
		}
	}
	state := map[string]int{}
	var visit func(string)
	visit = func(name string) {
		if state[name] == 1 {
			t.Fatalf("group cycle through %q", name)
		}
		if state[name] == 2 {
			return
		}
		state[name] = 1
		for _, ref := range routingChoices(t, groups, name) {
			if _, isGroup := groups[ref]; isGroup {
				visit(ref)
			}
		}
		state[name] = 2
	}
	for name := range groups {
		visit(name)
	}
}

func TestClientRoutingReferencePolicy(t *testing.T) {
	doc := routingDocument(t, routingConfig(t), false)
	if doc["mode"] != "rule" || doc["ipv6"] != false {
		t.Fatalf("wrong default client mode/IPv6: mode=%v ipv6=%v", doc["mode"], doc["ipv6"])
	}
	groups := routingGroups(t, doc)
	t.Run("groups", func(t *testing.T) {
		if len(groups) != 8 {
			t.Errorf("want eight policy groups, got %d", len(groups))
		}
		nodes := []string{"NodeKit-vless", "NodeKit-ss", "NodeKit-tuic", "NodeKit-hysteria2", "NodeKit-anytls"}
		for _, tc := range []struct {
			name, typ string
			choices   []string
		}{
			{"节点选择", "select", append(append([]string{"自动选择", "故障切换"}, nodes...), "DIRECT")},
			{"自动选择", "url-test", nodes},
			{"故障切换", "fallback", nodes},
			{"▶️ YouTube", "select", append([]string{"节点选择", "自动选择"}, nodes...)},
			{"📲 电报信息", "select", append([]string{"节点选择"}, nodes...)},
			{"🤖 ChatGPT", "select", nodes},
			{"🛑 全球拦截", "select", []string{"REJECT", "DIRECT"}},
			{"🐟 漏网之鱼", "select", append([]string{"节点选择", "DIRECT", "自动选择"}, nodes...)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := routingChoices(t, groups, tc.name)
				if groups[tc.name]["type"] != tc.typ || !reflect.DeepEqual(got, tc.choices) {
					t.Fatalf("wrong policy/default for %q: %v", tc.name, groups[tc.name])
				}
				if tc.typ != "select" && (groups[tc.name]["url"] != "https://www.gstatic.com/generate_204" || groups[tc.name]["interval"] != 300) {
					t.Fatal("existing probe behavior changed")
				}
			})
		}
	})
	t.Run("rules", func(t *testing.T) {
		want := []string{
			"GEOSITE,youtube,▶️ YouTube",
			"OR,((DOMAIN,gemini.google.com),(DOMAIN,bard.google.com),(GEOSITE,openai)),🤖 ChatGPT",
			"RULE-SET,applications,DIRECT",
			"DOMAIN,clash.razord.top,DIRECT",
			"DOMAIN,yacd.haishan.me,DIRECT",
			"RULE-SET,private,DIRECT",
			"RULE-SET,reject,🛑 全球拦截",
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
			"RULE-SET,telegramcidr,📲 电报信息",
			"GEOIP,LAN,DIRECT",
			"GEOIP,CN,DIRECT",
			"MATCH,🐟 漏网之鱼",
		}
		if got := routingStrings(t, doc["rules"]); !reflect.DeepEqual(got, want) {
			t.Fatalf("reference rules/order (including no QUIC block):\ngot  %q\nwant %q", got, want)
		}
	})
	t.Run("providers", func(t *testing.T) {
		providers, ok := doc["rule-providers"].(obj)
		if !ok {
			t.Fatal("missing referenced rule-providers")
		}
		behaviors := map[string]string{
			"reject": "domain", "icloud": "domain", "apple": "domain", "google": "domain", "proxy": "domain", "direct": "domain", "private": "domain",
			"telegramcidr": "ipcidr", "cncidr": "ipcidr", "lancidr": "ipcidr", "applications": "classical",
		}
		if len(providers) != 11 {
			t.Fatalf("want exactly 11 referenced providers, got %d", len(providers))
		}
		referenced := map[string]bool{}
		for _, rule := range routingStrings(t, doc["rules"]) {
			parts := strings.Split(rule, ",")
			if parts[0] == "RULE-SET" {
				referenced[parts[1]] = true
			}
		}
		if len(referenced) != 11 {
			t.Fatalf("want exactly 11 provider references, got %v", referenced)
		}
		paths := map[string]bool{}
		for name, behavior := range behaviors {
			provider, ok := providers[name].(obj)
			if !ok || !referenced[name] {
				t.Fatalf("missing or unreferenced provider %q", name)
			}
			if provider["type"] != "http" || provider["behavior"] != behavior || provider["interval"] != 86400 || provider["url"] != "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/"+name+".txt" {
				t.Fatalf("wrong provider settings for %q: %v", name, provider)
			}
			cache, ok := provider["path"].(string)
			clean := path.Clean(cache)
			if !ok || clean == "." || path.IsAbs(cache) || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsAny(cache, "\\:") || paths[clean] {
				t.Fatalf("provider %q needs a unique relative cache path, got %q", name, cache)
			}
			paths[clean] = true
		}
	})
	t.Run("graph", func(t *testing.T) { assertRoutingGraph(t, doc, "🤖 ChatGPT") })
}

func TestClientRoutingAICandidates(t *testing.T) {
	for _, tc := range []struct {
		name, country string
		nodes, want   []string
		disabled      int
	}{
		{"country_HK_overrides_custom_names", "HK", []string{"Tokyo", "US"}, []string{"REJECT"}, -1},
		{"flag", "", []string{"🇭🇰 relay"}, []string{"REJECT"}, -1},
		{"Chinese_marker", "", []string{"香港 relay"}, []string{"REJECT"}, -1},
		{"lowercase_hk", "", []string{"myhkrelay"}, []string{"REJECT"}, -1},
		{"uppercase_HK", "US", []string{"HK relay"}, []string{"REJECT"}, -1},
		{"mixed_case_hongkong", "", []string{"HoNgKoNg relay"}, []string{"REJECT"}, -1},
		{"eligible_unknown_country", "", []string{"Tokyo", "Singapore"}, []string{"Tokyo", "Singapore"}, -1},
		{"eligible_known_country", "US", []string{"West", "East"}, []string{"West", "East"}, -1},
		{"mixed_candidates", "", []string{"Tokyo", "🇭🇰 relay", "新加坡", "hK relay", "London"}, []string{"Tokyo", "新加坡", "London"}, -1},
		{"disabled_eligible_node_is_not_a_fallback", "", []string{"HK relay", "Tokyo"}, []string{"REJECT"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := routingConfig(t)
			c.CountryCode = tc.country
			for i := range c.Protocols {
				c.Protocols[i].Enabled = i < len(tc.nodes) && i != tc.disabled
				if i < len(tc.nodes) {
					c.Protocols[i].Name = tc.nodes[i]
				}
			}
			doc := routingDocument(t, c, false)
			if got := routingChoices(t, routingGroups(t, doc), "🤖 ChatGPT"); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("AI candidates: got %q, want %q", got, tc.want)
			}
			assertRoutingGraph(t, doc, "🤖 ChatGPT")
		})
	}
	t.Run("generated_display_name", func(t *testing.T) {
		c := routingConfig(t)
		c.Name = "HK host"
		doc := routingDocument(t, c, false)
		if got := routingChoices(t, routingGroups(t, doc), "🤖 ChatGPT"); !reflect.DeepEqual(got, []string{"REJECT"}) {
			t.Fatalf("generated HK node names escaped filtering: %v", got)
		}
	})
}

func TestClientRoutingGroupNameCollisions(t *testing.T) {
	for _, business := range []struct{ base, rule string }{
		{"▶️ YouTube", "GEOSITE,youtube,"},
		{"📲 电报信息", "RULE-SET,telegramcidr,"},
		{"🤖 ChatGPT", "OR,((DOMAIN,gemini.google.com),(DOMAIN,bard.google.com),(GEOSITE,openai)),"},
		{"🛑 全球拦截", "RULE-SET,reject,"},
		{"🐟 漏网之鱼", "MATCH,"},
	} {
		for _, collision := range []struct {
			name, want string
			nodes      []string
			disabled   bool
		}{
			{"base", business.base + " · NodeKit", []string{business.base}, false},
			{"several_suffixes", business.base + " · NodeKit 4", []string{business.base, business.base + " · NodeKit", business.base + " · NodeKit 2", business.base + " · NodeKit 3"}, false},
			{"disabled_node", business.base, []string{business.base}, true},
		} {
			t.Run(business.base+"/"+collision.name, func(t *testing.T) {
				c := routingConfig(t)
				for i, name := range collision.nodes {
					c.Protocols[i].Name = name
					c.Protocols[i].Enabled = !collision.disabled
				}
				doc := routingDocument(t, c, false)
				groups := routingGroups(t, doc)
				if _, ok := groups[collision.want]; !ok {
					t.Fatalf("missing collision-safe group %q", collision.want)
				}
				if len(groups) != 8 {
					t.Fatalf("collision changed group count: %d", len(groups))
				}
				found := false
				for _, rule := range routingStrings(t, doc["rules"]) {
					if rule == business.rule+collision.want {
						found = true
					}
				}
				if !found {
					t.Fatalf("rule did not use renamed group: want %q", business.rule+collision.want)
				}
				provider := routingDocument(t, c, true)
				if !reflect.DeepEqual(doc["proxies"], provider["proxies"]) {
					t.Fatal("collision handling changed published nodes")
				}
				for i, name := range collision.nodes {
					if !collision.disabled && doc["proxies"].([]any)[i].(obj)["name"] != name {
						t.Fatalf("collision renamed existing node %q", name)
					}
				}
				aiGroup := "🤖 ChatGPT"
				if business.base == aiGroup {
					aiGroup = collision.want
				}
				assertRoutingGraph(t, doc, aiGroup)
			})
		}
	}
	for _, reserved := range []string{"节点选择", "自动选择", "故障切换", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"} {
		t.Run("existing_reserved/"+reserved, func(t *testing.T) {
			c := routingConfig(t)
			c.Protocols[0].Name = reserved
			if _, err := Subscription(c, false); err == nil {
				t.Fatalf("existing reserved node name %q became valid", reserved)
			}
		})
	}
}

func TestClientRoutingEmptyAndIPv6Candidates(t *testing.T) {
	for _, tc := range []struct {
		name, country string
		ipv6          bool
		nodes, ai     []string
	}{
		{"no_nodes", "", false, []string{}, []string{"REJECT"}},
		{"IPv6_only", "", true, []string{"NodeKit-ss · IPv6", "NodeKit-tuic · IPv6"}, []string{"NodeKit-ss · IPv6", "NodeKit-tuic · IPv6"}},
		{"IPv6_only_HK", "HK", true, []string{"NodeKit-ss · IPv6", "NodeKit-tuic · IPv6"}, []string{"REJECT"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := routingConfig(t)
			c.CountryCode = tc.country
			for i := range c.Protocols {
				c.Protocols[i].Enabled = false
			}
			c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: tc.ipv6, Address: "2001:4860:4860::8888", Protocols: []string{"ss", "tuic"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
			doc := routingDocument(t, c, false)
			var names = []string{}
			for _, raw := range doc["proxies"].([]any) {
				names = append(names, raw.(obj)["name"].(string))
			}
			if !reflect.DeepEqual(names, tc.nodes) || doc["ipv6"] != tc.ipv6 {
				t.Fatalf("wrong independent IPv6 selection: nodes=%v ipv6=%v", names, doc["ipv6"])
			}
			choices := tc.nodes
			if len(choices) == 0 {
				choices = []string{"REJECT"}
			}
			groups := routingGroups(t, doc)
			for name, want := range map[string][]string{
				"节点选择":       append(append([]string{"自动选择", "故障切换"}, choices...), "DIRECT"),
				"自动选择":       choices,
				"故障切换":       choices,
				"▶️ YouTube": append([]string{"节点选择", "自动选择"}, choices...),
				"📲 电报信息":     append([]string{"节点选择"}, choices...),
				"🤖 ChatGPT":  tc.ai,
				"🛑 全球拦截":     {"REJECT", "DIRECT"},
				"🐟 漏网之鱼":     append([]string{"节点选择", "DIRECT", "自动选择"}, choices...),
			} {
				if got := routingChoices(t, groups, name); !reflect.DeepEqual(got, want) {
					t.Fatalf("group %q: got %q, want %q", name, got, want)
				}
			}
			assertRoutingGraph(t, doc, "🤖 ChatGPT")
		})
	}
}

func TestClientRoutingProviderIsolation(t *testing.T) {
	for _, scenario := range []string{"default", "HK", "collision", "empty", "IPv6"} {
		t.Run(scenario, func(t *testing.T) {
			c := routingConfig(t)
			switch scenario {
			case "HK":
				c.CountryCode = "HK"
			case "collision":
				c.Protocols[0].Name = "🤖 ChatGPT"
			case "empty":
				for i := range c.Protocols {
					c.Protocols[i].Enabled = false
				}
			case "IPv6":
				c = ipv6Config(t)
			}
			before := c.Clone()
			full := routingDocument(t, c, false)
			provider := routingDocument(t, c, true)
			if len(provider) != 1 || !reflect.DeepEqual(provider["proxies"], full["proxies"]) {
				t.Fatal("provider must contain only unchanged proxies")
			}
			if !reflect.DeepEqual(c, before) {
				t.Fatal("subscription rendering mutated configuration")
			}
		})
	}
}
