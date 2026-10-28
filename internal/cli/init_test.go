package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDryRunInitAndRefusalToOverwrite(t *testing.T) {
	root := t.TempDir()
	var out, err bytes.Buffer
	args := []string{"--root", root, "init", "--domain", "node.example.com", "--dry-run"}
	if code := Run(context.Background(), args, bytes.NewBuffer(nil), &out, &err); code != 0 {
		t.Fatal(code, err.String())
	}
	p := filepath.Join(root, "etc/nodekit/bootstrap.json")
	before, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	out.Reset()
	err.Reset()
	if code := Run(context.Background(), args, bytes.NewBuffer(nil), &out, &err); code == 0 {
		t.Fatal("overwrote initialization")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("changed previous credentials")
	}
}
