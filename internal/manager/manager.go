package manager

import (
	"context"
	"errors"
	"nodekit/internal/calendar"
	"nodekit/internal/meter"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"nodekit/internal/store"
	"sync"
	"time"
)

type Core interface {
	Snapshot(context.Context) (meter.Sample, error)
	Check(context.Context, []byte) error
	Apply(context.Context, string) error
	Health(context.Context, model.Config) error
}
type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}
type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now().UTC() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type Manager struct {
	db              *store.Store
	core            Core
	clock           Clock
	paths           render.Paths
	mu              sync.Mutex
	PrepareListener func(model.Config, model.Config) (commit func(), abort func(), err error)
}

func New(db *store.Store, core Core, clock Clock, paths render.Paths) (*Manager, error) {
	if db == nil || core == nil || paths.WorkDir == "" {
		return nil, errors.New("manager dependencies missing")
	}
	if clock == nil {
		clock = wallClock{}
	}
	return &Manager{db: db, core: core, clock: clock, paths: paths}, nil
}
func schedule(c model.Config) meter.Schedule {
	return meter.Schedule{Day: c.ResetDay, Hour: c.ResetHour}
}
func (m *Manager) sample(ctx context.Context, reset bool) error {
	v, e := m.core.Snapshot(ctx)
	if e != nil {
		_ = m.db.Update(func(r *store.Record) error {
			r.SamplingError = "core unavailable; last saved usage retained"
			if !r.Meter.Next.IsZero() && !m.clock.Now().Before(r.Meter.Next) {
				start, next, err := calendar.Bounds(m.clock.Now(), r.Config.ResetDay, r.Config.ResetHour)
				if err != nil {
					return err
				}
				r.Meter.PeriodStart = start
				r.Meter.Next = next
				r.Meter.Upload = 0
				r.Meter.Download = 0
				r.Meter.PendingBoundary = true
				r.Meter.Gap = "core unavailable across monthly boundary"
			}
			return nil
		})
		return e
	}
	return m.db.Update(func(r *store.Record) error {
		var next meter.State
		var err error
		if reset {
			next, err = meter.Reset(r.Meter, v, schedule(r.Config))
		} else {
			next, err = meter.Advance(r.Meter, v, schedule(r.Config))
		}
		if err != nil {
			return err
		}
		r.Meter = next
		r.SamplingError = ""
		return nil
	})
}
func (m *Manager) Flush(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sample(ctx, false)
}
func (m *Manager) Reset(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sample(ctx, true)
}
func (m *Manager) View(ctx context.Context) (store.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, e := m.db.Load()
	if e != nil {
		return r, e
	}
	if r.Meter.LastSample.IsZero() || m.clock.Now().Sub(r.Meter.LastSample) >= 5*time.Second || (!r.Meter.Next.IsZero() && !m.clock.Now().Before(r.Meter.Next)) {
		_ = m.sample(ctx, false)
		return m.db.Load()
	}
	return r, nil
}
func (m *Manager) Run(ctx context.Context) error {
	if e := m.Recover(ctx); e != nil {
		return e
	}
	for {
		_ = m.Flush(ctx)
		r, e := m.db.Load()
		if e != nil {
			return e
		}
		delay := 5 * time.Second
		if until := r.Meter.Next.Sub(m.clock.Now()); until > 0 && until < delay {
			delay = until
		}
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = m.Flush(flushCtx)
			cancel()
			return nil
		case <-m.clock.After(delay):
		}
	}
}
