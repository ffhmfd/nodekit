package meter

import (
	"math"
	"testing"
	"time"
)

func ts(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
func TestEpochAndCounterRecovery(t *testing.T) {
	sched := Schedule{Day: 1, Hour: 8}
	s := State{}
	sample := Sample{Epoch: "a", StartedAt: ts("2026-10-02T00:00:00Z"), At: ts("2026-10-02T01:00:00Z"), Upload: 100, Download: 200}
	s, e := Advance(s, sample, sched)
	if e != nil {
		t.Fatal(e)
	}
	sample.At = sample.At.Add(5 * time.Second)
	sample.Upload = 150
	sample.Download = 280
	s, e = Advance(s, sample, sched)
	if e != nil || s.Upload != 150 || s.Download != 280 {
		t.Fatal(s, e)
	}
	s, e = Advance(s, sample, sched)
	if e != nil || s.Upload != 150 {
		t.Fatal("duplicate", s, e)
	}
	sample.Epoch = "b"
	sample.StartedAt = sample.At
	sample.Upload = 10
	sample.Download = 20
	s, e = Advance(s, sample, sched)
	if e != nil || s.Upload != 160 || s.Download != 300 {
		t.Fatal("restart", s, e)
	}
	sample.Upload = 2
	sample.Download = 3
	s, e = Advance(s, sample, sched)
	if e != nil || s.Gap == "" || s.Upload < 160 {
		t.Fatal("counter reset", s, e)
	}
}
func TestBoundariesAndManualReset(t *testing.T) {
	sched := Schedule{1, 8}
	sample := Sample{Epoch: "a", StartedAt: ts("2026-10-01T00:00:00Z"), At: ts("2026-10-31T23:59:58Z"), Upload: 100, Download: 200}
	s, e := Advance(State{}, sample, sched)
	if e != nil {
		t.Fatal(e)
	}
	sample.At = ts("2026-11-01T00:00:02Z")
	sample.Upload = 110
	sample.Download = 220
	s, e = Advance(s, sample, sched)
	if e != nil || s.Upload != 10 || s.Download != 20 {
		t.Fatal("boundary", s, e)
	}
	next := s.Next
	s, e = Reset(s, sample, sched)
	if e != nil || s.Upload != 0 || s.Download != 0 || !s.Next.Equal(next) {
		t.Fatal("manual", s, e)
	}
	sample.At = ts("2026-12-01T02:00:00Z")
	sample.Upload = 10000
	s, e = Advance(s, sample, sched)
	if e != nil || s.Upload != 0 || s.Gap == "" {
		t.Fatal("missing interval", s, e)
	}
	sample.At = ts("2026-10-01T00:00:00Z")
	old := s.PeriodStart
	s, e = Advance(s, sample, sched)
	if e != nil || s.PeriodStart.Before(old) {
		t.Fatal("clock rollback", s, e)
	}
}
func TestOverflowAndFailureLeaveInputUntouched(t *testing.T) {
	sched := Schedule{1, 0}
	sample := Sample{Epoch: "a", StartedAt: time.Now(), At: time.Now(), Upload: 1}
	s, _ := Advance(State{}, sample, sched)
	s.Upload = math.MaxInt64
	sample.Upload = 2
	if _, e := Advance(s, sample, sched); e == nil {
		t.Fatal("overflow accepted")
	}
	sample.Upload = -1
	if _, e := Advance(s, sample, sched); e == nil {
		t.Fatal("negative counter accepted")
	}
}

func TestRescheduleAndPendingBoundary(t *testing.T) {
	sample := Sample{Epoch: "a", StartedAt: ts("2026-10-10T00:00:00Z"), At: ts("2026-10-10T01:00:00Z"), Upload: 100, Download: 200}
	s, e := Advance(State{}, sample, Schedule{1, 8})
	if e != nil {
		t.Fatal(e)
	}
	s, e = Reschedule(s, sample.At, Schedule{15, 8})
	if e != nil || s.Upload != 100 || !s.Next.Equal(ts("2026-10-15T00:00:00Z")) {
		t.Fatal("reschedule lost traffic", s, e)
	}
	s.PeriodStart = ts("2026-11-01T00:00:00Z")
	s.Next = ts("2026-12-01T00:00:00Z")
	s.Upload = 0
	s.Download = 0
	s.PendingBoundary = true
	sample.At = ts("2026-11-01T10:00:00Z")
	sample.Upload = 10000
	s, e = Advance(s, sample, Schedule{1, 8})
	if e != nil || s.Upload != 0 || s.PendingBoundary {
		t.Fatal("unobserved old traffic entered new month", s, e)
	}
	sample.Upload = 10020
	sample.At = sample.At.Add(5 * time.Second)
	s, e = Advance(s, sample, Schedule{1, 8})
	if e != nil || s.Upload != 20 {
		t.Fatal("new traffic missing", s, e)
	}
}
