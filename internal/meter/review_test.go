package meter

import (
	"testing"
	"time"
)

func TestOneDirectionCounterRollback(t *testing.T) {
	v := Sample{Epoch: "one", StartedAt: ts("2026-10-02T01:00:00Z"), At: ts("2026-10-02T01:00:01Z"), Upload: 100, Download: 200}
	s, e := Advance(State{}, v, Schedule{1, 0})
	if e != nil {
		t.Fatal(e)
	}
	v.At = v.At.Add(time.Second)
	v.Upload = 2
	v.Download = 210
	s, e = Advance(s, v, Schedule{1, 0})
	if e != nil || s.Upload != 102 || s.Download != 210 {
		t.Fatalf("unaffected direction counted twice: %d/%d %v", s.Upload, s.Download, e)
	}
}
func TestResetRejectsClockRollback(t *testing.T) {
	v := Sample{Epoch: "one", StartedAt: ts("2026-10-02T01:00:00Z"), At: ts("2026-10-02T12:00:00Z"), Upload: 100}
	s, _ := Advance(State{}, v, Schedule{1, 0})
	v.At = v.At.Add(-time.Hour)
	v.Upload = 150
	next, e := Reset(s, v, Schedule{1, 0})
	if e == nil || next.Upload != 100 || next.RawUpload != 100 {
		t.Fatal("reset succeeded without current baseline")
	}
}
