package store

import (
	"errors"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAtomicPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	cfg, _ := model.New()
	e = s.Update(func(r *Record) error { r.Config = cfg; r.Meter.Upload = 42; return nil })
	if e != nil {
		t.Fatal(e)
	}
	e = s.Update(func(r *Record) error { r.Meter.Upload = 999; return errors.New("rollback") })
	if e == nil {
		t.Fatal("rollback accepted")
	}
	r, e := s.Load()
	if e != nil || r.Meter.Upload != 42 {
		t.Fatal("lost atomicity", r.Meter.Upload, e)
	}
	_ = s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r, e = s.Load()
	if e != nil || r.Meter.Upload != 42 || r.Config.Token != cfg.Token {
		t.Fatal("lost persistence", e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.Update(func(r *Record) error { r.Meter.Upload++; return nil }); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	r, _ = s.Load()
	if r.Meter.Upload != 62 {
		t.Fatal("lost increments", r.Meter.Upload)
	}
}

func TestBackupIncludesWAL(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(filepath.Join(dir, "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Update(func(r *Record) error { r.Meter.Upload = 12345; return nil }); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "backup.db")
	if e = s.Backup(path); e != nil {
		t.Fatal(e)
	}
	copy, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer copy.Close()
	r, e := copy.Load()
	if e != nil || r.Meter.Upload != 12345 {
		t.Fatal("WAL missing from backup", e)
	}
}

func TestDatabaseAbortKeepsCounterBaseline(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Update(func(r *Record) error { r.Meter.Upload = 10; r.Meter.RawUpload = 20; return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER refuse_update BEFORE UPDATE ON state BEGIN SELECT RAISE(ABORT, 'storage failure'); END"); e != nil {
		t.Fatal(e)
	}
	if e = s.Update(func(r *Record) error { r.Meter.Upload = 100; r.Meter.RawUpload = 200; return nil }); e == nil {
		t.Fatal("injected storage failure ignored")
	}
	r, e := s.Load()
	if e != nil || r.Meter.Upload != 10 || r.Meter.RawUpload != 20 {
		t.Fatal("failed commit advanced baseline", r.Meter, e)
	}
}

func TestInitializePublishesCompleteRecordWithoutOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	c, _ := model.New()
	c.Name = "original"
	if e := Initialize(path, Record{Config: c}); e != nil {
		t.Fatal(e)
	}
	c.Name = "replacement"
	if e := Initialize(path, Record{Config: c}); e == nil {
		t.Fatal("replaced initialized database")
	}
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r, e := s.Load()
	if e != nil || r.Config.Name != "original" {
		t.Fatal("initial database changed", e)
	}
	bad := filepath.Join(t.TempDir(), "invalid.db")
	if e = Initialize(bad, Record{}); e == nil {
		t.Fatal("published incomplete record")
	}
	if _, e = os.Stat(bad); !os.IsNotExist(e) {
		t.Fatal("invalid initialization left final database")
	}
}
