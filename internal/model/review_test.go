package model

import "testing"

func TestConfigClonePreservesPreviousBindings(t *testing.T) {
	c, _ := New()
	old := c.Clone()
	c.Protocols[0].Port = 25000
	c.Protocols[1].Enabled = false
	if old.Protocols[0].Port != 24441 || !old.Protocols[1].Enabled {
		t.Fatal("old configuration shares mutable protocol slice")
	}
}
