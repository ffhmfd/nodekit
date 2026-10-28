package calendar

import (
	"testing"
	"time"
)

func TestMonthlyBounds(t *testing.T) {
	for _, v := range []struct{ now, start, next string }{
		{"2027-02-28T00:00:00Z", "2027-02-28T00:00:00Z", "2027-03-31T00:00:00Z"},
		{"2028-02-28T12:00:00Z", "2028-01-31T00:00:00Z", "2028-02-29T00:00:00Z"},
		{"2028-02-29T00:00:00Z", "2028-02-29T00:00:00Z", "2028-03-31T00:00:00Z"},
	} {
		now, _ := time.Parse(time.RFC3339, v.now)
		s, n, e := Bounds(now, 31, 8)
		if e != nil || s.UTC().Format(time.RFC3339) != v.start || n.UTC().Format(time.RFC3339) != v.next {
			t.Fatalf("%s: %v %v %v", v.now, s, n, e)
		}
	}
}
func TestInvalidSchedule(t *testing.T) {
	for _, v := range [][2]int{{0, 8}, {32, 8}, {1, 24}, {1, -1}} {
		if _, _, e := Bounds(time.Now(), v[0], v[1]); e == nil {
			t.Fatal("invalid schedule accepted")
		}
	}
}
