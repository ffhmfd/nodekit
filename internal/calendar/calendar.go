package calendar

import (
	"errors"
	"time"
	_ "time/tzdata"
)

func Bounds(now time.Time, day, hour int) (time.Time, time.Time, error) {
	if day < 1 || day > 31 || hour < 0 || hour > 23 {
		return time.Time{}, time.Time{}, errors.New("invalid reset day/hour")
	}
	loc, e := time.LoadLocation("Asia/Shanghai")
	if e != nil {
		return time.Time{}, time.Time{}, e
	}
	n := now.In(loc)
	boundary := func(y int, m time.Month) time.Time {
		last := time.Date(y, m+1, 0, 0, 0, 0, 0, loc).Day()
		d := day
		if d > last {
			d = last
		}
		return time.Date(y, m, d, hour, 0, 0, 0, loc).UTC()
	}
	current := boundary(n.Year(), n.Month())
	if now.Before(current) {
		return boundary(n.Year(), n.Month()-1), current, nil
	}
	return current, boundary(n.Year(), n.Month()+1), nil
}
