package render

import (
	"gopkg.in/yaml.v3"
	"nodekit/internal/model"
	"testing"
)

func TestDisplayNamesUpdateAllGroupReferences(t *testing.T) {
	c, _ := model.New()
	if err := c.SetDisplayDefaults("host", "US"); err != nil {
		t.Fatal(err)
	}
	c.Protocols[0].Name = "custom REALITY"
	for _, provider := range []bool{false, true} {
		data, err := Subscription(c, provider)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		yaml.Unmarshal(data, &doc)
		names := map[string]bool{}
		for _, v := range doc["proxies"].([]any) {
			names[v.(map[string]any)["name"].(string)] = true
		}
		if !names["custom REALITY"] || !names["🇺🇸 host · HY2"] {
			t.Fatal("incorrect node names")
		}
		if provider {
			continue
		}
		for _, v := range doc["proxy-groups"].([]any) {
			g := v.(map[string]any)
			for _, ref := range g["proxies"].([]any) {
				s := ref.(string)
				if s != "自动选择" && s != "故障切换" && !names[s] {
					t.Fatal("stale group reference", s)
				}
			}
		}
	}
}
