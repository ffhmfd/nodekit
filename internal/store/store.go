package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	_ "modernc.org/sqlite"
	"nodekit/internal/meter"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Operation struct {
	ID, Phase, Error string
	Old, New         model.Config
}
type Record struct {
	Config         model.Config      `json:"config"`
	Meter          meter.State       `json:"meter"`
	Operation      *Operation        `json:"operation,omitempty"`
	LastError      string            `json:"last_error,omitempty"`
	SamplingError  string            `json:"sampling_error,omitempty"`
	OperationPhase string            `json:"operation_phase,omitempty"`
	Certificate    CertificateStatus `json:"certificate"`
}

type CertificateStatus struct {
	Expires     time.Time `json:"expires"`
	LastAttempt time.Time `json:"last_attempt"`
	NextAttempt time.Time `json:"next_attempt"`
	Error       string    `json:"error,omitempty"`
	Mode        string    `json:"mode"`
	Failures    int       `json:"failures"`
}
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func Open(path string) (*Store, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	_ = f.Close()
	if e = os.Chmod(path, 0600); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)", `INSERT OR IGNORE INTO state VALUES(1,'{}')`} {
		if _, e = db.Exec(q); e != nil {
			_ = db.Close()
			return nil, e
		}
	}
	return &Store{db: db}, nil
}

// Initialize builds and checkpoints a private database before publishing it.
// Linking with an exclusive destination makes an interrupted initializer
// retryable and prevents replacement of an existing user's state.
func Initialize(path string, record Record) error {
	if e := record.Config.Validate(); e != nil {
		return e
	}
	if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return errors.New("database already exists")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	dir, e := os.MkdirTemp(filepath.Dir(path), ".initialize-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	temp := filepath.Join(dir, "state.db")
	db, e := Open(temp)
	if e != nil {
		return e
	}
	if e = db.Update(func(r *Record) error { *r = record; return nil }); e != nil {
		db.Close()
		return e
	}
	if _, e = db.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		db.Close()
		return e
	}
	if e = db.Close(); e != nil {
		return e
	}
	f, e := os.OpenFile(temp, os.O_RDWR, 0)
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return e
	}
	if e = os.Link(temp, path); e != nil {
		return e
	}
	parent, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer parent.Close()
	return parent.Sync()
}
func (s *Store) Load() (Record, error) {
	var r Record
	var b []byte
	e := s.db.QueryRow("SELECT data FROM state WHERE id=1").Scan(&b)
	if e != nil {
		return r, e
	}
	e = json.Unmarshal(b, &r)
	return r, e
}
func (s *Store) Update(fn func(*Record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var b []byte
	if e = tx.QueryRow("SELECT data FROM state WHERE id=1").Scan(&b); e != nil {
		return e
	}
	var r Record
	if e = json.Unmarshal(b, &r); e != nil {
		return e
	}
	if e = fn(&r); e != nil {
		return e
	}
	b, e = json.Marshal(r)
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return errors.New("state too large")
	}
	if _, e = tx.Exec("UPDATE state SET data=? WHERE id=1", b); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Backup(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return errors.New("backup destination exists")
	}
	_, e := s.db.Exec("VACUUM INTO ?", path)
	if e != nil {
		return e
	}
	return os.Chmod(path, 0600)
}
