package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotUsesExactCumulativeCounters(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "c.sock")
	ln, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	body := `{"uploadTotal":9007199254740993,"downloadTotal":42,"connections":[]}`
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })}
	go srv.Serve(ln)
	defer srv.Close()
	c := Client{Socket: sock}
	s, e := c.Snapshot(context.Background())
	if e != nil || s.Upload != 9007199254740993 || s.Download != 42 || s.Epoch == "" || s.StartedAt.IsZero() {
		t.Fatal(s, e)
	}
	for _, b := range []string{`{"uploadTotal":-1,"downloadTotal":2}`, `{}`, `{invalid`} {
		body = b
		if _, e := c.Snapshot(context.Background()); e == nil {
			t.Fatal("accepted invalid counters")
		}
	}
}
func TestUnreachableCoreDoesNotFabricateSample(t *testing.T) {
	c := Client{Socket: filepath.Join(t.TempDir(), "absent.sock")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := c.Snapshot(ctx); e == nil {
		t.Fatal("unreachable core accepted")
	}
}
