package model

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestTrafficMultiplierValidation(t *testing.T) {
	for _, value := range []int{-1, 0, 1, 2, 3, 100} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			c, _ := New()
			if err := json.Unmarshal([]byte(fmt.Sprintf(`{"traffic_multiplier":%d}`, value)), &c); err != nil {
				t.Fatal(err)
			}
			err := c.Validate()
			if (err == nil) != (value >= 0 && value <= 2) {
				t.Fatalf("multiplier %d validation: %v", value, err)
			}
		})
	}
}

func TestTrafficMultiplierJSONRoundTrip(t *testing.T) {
	c, _ := New()
	if err := json.Unmarshal([]byte(`{"traffic_multiplier":2}`), &c); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c.Clone())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["traffic_multiplier"] != float64(2) {
		t.Fatal("config export lost multiplier", string(b))
	}
}
