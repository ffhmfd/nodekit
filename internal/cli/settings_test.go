package cli

import (
	"context"
	"errors"
	"nodekit/internal/model"
	"reflect"
	"testing"
)

func TestAdvancedSettingsPreserveIdentityAndValidateProbe(t *testing.T) {
	c, _ := model.New()
	original := c.Clone()
	offline := func(context.Context, model.Reality) error { return errors.New("target unreachable") }
	if err := applyAdvancedSetting(context.Background(), &c, "reality-sni", "example.com", offline); err == nil || !reflect.DeepEqual(c, original) {
		t.Fatal("failed probe changed config")
	}
	probe := func(_ context.Context, r model.Reality) error {
		if r.ServerName != "example.com" || r.Target != "example.com:443" {
			t.Fatal("probe got stale target")
		}
		return nil
	}
	if err := applyAdvancedSetting(context.Background(), &c, "reality-sni", "example.com", probe); err != nil {
		t.Fatal(err)
	}
	if c.Reality.PrivateKey != original.Reality.PrivateKey || c.Token != original.Token {
		t.Fatal("credentials changed")
	}
	if err := applyAdvancedSetting(context.Background(), &c, "country", "JP", nil); err != nil {
		t.Fatal(err)
	}
	if err := applyAdvancedSetting(context.Background(), &c, "name-style", "flag-host", nil); err != nil {
		t.Fatal(err)
	}
	if c.NodeName(c.Protocols[0]) != "🇯🇵 NodeKit · VLESS" {
		t.Fatal("display setting not applied")
	}
	before := c.Clone()
	if applyAdvancedSetting(context.Background(), &c, "country", "invalid", nil) == nil || !reflect.DeepEqual(c, before) {
		t.Fatal("invalid country committed")
	}
}
