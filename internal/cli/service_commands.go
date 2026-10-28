package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"nodekit/internal/core"
	"nodekit/internal/platform"
	"nodekit/internal/render"
	"os"
	"path/filepath"
)

// These commands run as the service UID. Root orchestration never opens the
// service-controlled SQLite database with elevated privileges.
func serviceDataCommand(ctx context.Context, p paths, command string, out io.Writer) error {
	if _, e := os.Stat(filepath.Join(p.Data, "state.db")); e != nil {
		return e
	}
	db, e := p.db()
	if e != nil {
		return e
	}
	defer db.Close()
	r, e := db.Load()
	if e != nil {
		return e
	}
	if e = r.Config.Validate(); e != nil {
		return e
	}
	switch command {
	case "inspect":
		return json.NewEncoder(out).Encode(r.Config)
	case "snapshot":
		f, e := os.CreateTemp(p.Data, ".snapshot-*.db")
		if e != nil {
			return e
		}
		path := f.Name()
		f.Close()
		os.Remove(path)
		defer os.Remove(path)
		if e = db.Backup(path); e != nil {
			return e
		}
		f, e = os.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		_, e = io.Copy(out, f)
		return e
	case "prepare":
		b, e := render.Server(r.Config, p.render())
		if e != nil {
			return e
		}
		client := &core.Client{Binary: p.Core, WorkDir: p.Data, Socket: p.render().Socket}
		if e = client.Check(ctx, b); e != nil {
			return e
		}
		return platform.RestoreAtomic(p.Data, "active.yaml", b, os.Geteuid(), os.Getegid())
	}
	return errors.New("unsupported service data command")
}
