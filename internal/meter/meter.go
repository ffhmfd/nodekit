package meter

import (
	"errors"
	"math"
	"nodekit/internal/calendar"
	"time"
)

type Schedule struct{ Day, Hour int }
type Sample struct {
	Epoch            string
	StartedAt, At    time.Time
	Upload, Download int64
}
type State struct {
	Epoch           string    `json:"epoch"`
	StartedAt       time.Time `json:"started_at"`
	LastSample      time.Time `json:"last_sample"`
	RawUpload       int64     `json:"raw_upload"`
	RawDownload     int64     `json:"raw_download"`
	Upload          int64     `json:"upload"`
	Download        int64     `json:"download"`
	PeriodStart     time.Time `json:"period_start"`
	Next            time.Time `json:"next"`
	LastReset       time.Time `json:"last_reset"`
	Gap             string    `json:"gap,omitempty"`
	PendingBoundary bool      `json:"pending_boundary,omitempty"`
}

func Advance(s State, v Sample, schedule Schedule) (State, error) {
	if v.Epoch == "" || v.At.IsZero() || v.StartedAt.IsZero() || v.Upload < 0 || v.Download < 0 {
		return s, errors.New("invalid counter sample")
	}
	start, next, e := calendar.Bounds(v.At, schedule.Day, schedule.Hour)
	if e != nil {
		return s, e
	}
	if !s.LastSample.IsZero() && v.At.Before(s.LastSample) {
		s.Gap = "clock moved backwards; sample ignored"
		return s, nil
	}
	first := s.Epoch == ""
	newEpoch := s.Epoch != v.Epoch
	boundary := !s.Next.IsZero() && !v.At.Before(s.Next)
	du, dd := v.Upload, v.Download
	if !newEpoch {
		if v.Upload < s.RawUpload || v.Download < s.RawDownload {
			s.Gap = "core counters reset within same process"
		}
		if v.Upload >= s.RawUpload {
			du = v.Upload - s.RawUpload
		}
		if v.Download >= s.RawDownload {
			dd = v.Download - s.RawDownload
		}
	}
	if first {
		s.PeriodStart = start
		s.Next = next
		if v.StartedAt.Before(start) {
			du = 0
			dd = 0
			s.Gap = "initial counters span an unobserved period"
		}
	}
	if boundary {
		s.Upload = 0
		s.Download = 0
		s.PeriodStart = start
		s.Next = next
		s.LastReset = start
		if newEpoch && !v.StartedAt.Before(start) {
			du = v.Upload
			dd = v.Download
		} else if newEpoch || v.At.Sub(s.LastSample) > 6*time.Second {
			du = 0
			dd = 0
			s.Gap = "unobserved traffic crossed monthly boundary"
		}
	}
	if newEpoch && !first {
		s.Gap = "core restarted; final unsampled traffic may be missing"
		if v.StartedAt.Before(s.PeriodStart) {
			du = 0
			dd = 0
			s.Gap = "new core epoch spans unobserved period"
		}
	}
	if s.PendingBoundary {
		if newEpoch && !v.StartedAt.Before(s.PeriodStart) {
			du = v.Upload
			dd = v.Download
		} else {
			du = 0
			dd = 0
		}
		s.PendingBoundary = false
	}
	if du > math.MaxInt64-s.Upload || dd > math.MaxInt64-s.Download {
		return s, errors.New("traffic counter overflow")
	}
	s.Upload += du
	s.Download += dd
	s.RawUpload = v.Upload
	s.RawDownload = v.Download
	s.Epoch = v.Epoch
	s.StartedAt = v.StartedAt
	s.LastSample = v.At
	return s, nil
}
func Reset(s State, v Sample, schedule Schedule) (State, error) {
	if !s.LastSample.IsZero() && v.At.Before(s.LastSample) {
		return s, errors.New("clock moved backwards; correct the clock before resetting usage")
	}
	n, e := Advance(s, v, schedule)
	if e != nil {
		return s, e
	}
	n.Upload = 0
	n.Download = 0
	n.LastReset = v.At
	return n, nil
}
func Reschedule(s State, now time.Time, schedule Schedule) (State, error) {
	_, next, e := calendar.Bounds(now, schedule.Day, schedule.Hour)
	if e != nil {
		return s, e
	}
	s.Next = next
	return s, nil
}
