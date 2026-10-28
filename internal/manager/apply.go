package manager

import (
	"context"
	"errors"
	"fmt"
	"nodekit/internal/meter"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"time"
)

func atomicFile(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (m *Manager) restore(ctx context.Context, old model.Config) error {
	b, e := render.Server(old, m.paths)
	if e != nil {
		return e
	}
	path := filepath.Join(m.paths.WorkDir, "active.yaml")
	if e = atomicFile(path, b); e != nil {
		return e
	}
	if e = m.core.Apply(ctx, path); e != nil {
		return e
	}
	return m.core.Health(ctx, old)
}
func (m *Manager) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, e := m.db.Load()
	if e != nil {
		return e
	}
	if r.Operation == nil {
		return nil
	}
	if e = m.restore(ctx, r.Operation.Old); e != nil {
		return fmt.Errorf("pending operation recovery failed: %w", e)
	}
	return m.db.Update(func(r *store.Record) error {
		r.Config = r.Operation.Old
		r.Operation = nil
		r.LastError = ""
		return nil
	})
}
func (m *Manager) Change(ctx context.Context, c model.Config) error {
	return m.change(ctx, c, false)
}

// ChangeManaged is called only by the authenticated root coordination endpoint.
func (m *Manager) ChangeManaged(ctx context.Context, c model.Config) error {
	return m.change(ctx, c, true)
}

func (m *Manager) change(ctx context.Context, c model.Config, coordinated bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, e := m.db.Load()
	if e != nil {
		return e
	}
	if r.Operation != nil {
		return errors.New("unfinished operation requires recovery")
	}
	if c.Revision != r.Config.Revision {
		return errors.New("stale configuration revision")
	}
	if !coordinated && (r.Config.ManagedDNS || c.ManagedDNS) && model.DNSFieldsChanged(r.Config, c) {
		return errors.New("managed DNS changes require the root DNS coordinator")
	}
	if e = c.Validate(); e != nil {
		return e
	}
	old := r.Config
	c.Revision++
	b, e := render.Server(c, m.paths)
	if e != nil {
		return e
	}
	if e = m.core.Check(ctx, b); e != nil {
		return e
	}
	commitListener, abortListener := func() {}, func() {}
	if m.PrepareListener != nil {
		commitListener, abortListener, e = m.PrepareListener(old, c)
		if e != nil {
			return e
		}
	}
	listenerCommitted := false
	defer func() {
		if !listenerCommitted {
			abortListener()
		}
	}()
	_ = m.sample(ctx, false)
	path := filepath.Join(m.paths.WorkDir, fmt.Sprintf("candidate-%d.yaml", c.Revision))
	if e = atomicFile(path, b); e != nil {
		return e
	}
	defer os.Remove(path)
	if e = m.db.Update(func(r *store.Record) error {
		r.Operation = &store.Operation{ID: fmt.Sprint(time.Now().UnixNano()), Phase: "prepared", Old: old, New: c}
		return nil
	}); e != nil {
		return e
	}
	fail := func(cause error) error {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		restoreErr := m.restore(rollbackCtx, old)
		dbErr := m.db.Update(func(r *store.Record) error {
			if restoreErr == nil {
				r.Operation = nil
				r.LastError = "configuration change rolled back"
			} else {
				r.Operation.Phase = "rollback_failed"
				r.Operation.Error = restoreErr.Error()
				r.LastError = "rollback failed; run recovery"
			}
			return nil
		})
		return errors.Join(cause, restoreErr, dbErr)
	}
	if e = m.core.Apply(ctx, path); e != nil {
		return fail(e)
	}
	if e = m.db.Update(func(r *store.Record) error { r.Operation.Phase = "applied"; return nil }); e != nil {
		return fail(e)
	}
	if e = m.core.Health(ctx, c); e != nil {
		return fail(e)
	}
	if e = atomicFile(filepath.Join(m.paths.WorkDir, "active.yaml"), b); e != nil {
		return fail(e)
	}
	if e = m.db.Update(func(r *store.Record) error {
		if c.ResetDay != old.ResetDay || c.ResetHour != old.ResetHour {
			s, err := meter.Reschedule(r.Meter, m.clock.Now(), schedule(c))
			if err != nil {
				return err
			}
			r.Meter = s
		}
		r.Config = c
		r.Operation = nil
		r.LastError = ""
		return nil
	}); e != nil {
		return fail(e)
	}
	commitListener()
	listenerCommitted = true
	return nil
}
