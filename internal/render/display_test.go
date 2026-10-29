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
		groups := routingGroups(t, doc)
		for _, name := range []string{"节点选择", "自动选择", "故障切换"} {
			refs := routingChoices(t, groups, name)
			for node := range names {
				found := false
				for _, ref := range refs {
					found = found || ref == node
				}
				if !found {
					t.Fatalf("group %q omitted displayed node %q", name, node)
				}
			}
		}
		assertRoutingGraph(t, doc, "🤖 ChatGPT")
	}
}
