package testutil

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func Release(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "release.tar.gz")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	meta, _ := json.Marshal(map[string]any{"version": "v0.1.0", "arch": runtime.GOARCH, "core_version": "v1.19.33", "schema": 1})
	for name, b := range map[string][]byte{"nodekit": []byte("#!/bin/sh\nexit 0\n"), "mihomo": []byte("#!/bin/sh\nexit 0\n"), "release.json": meta} {
		if e = tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(b))}); e != nil {
			t.Fatal(e)
		}
		if _, e = tw.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	tw.Close()
	gz.Close()
	f.Close()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(b)
	return path, fmt.Sprintf("%x", sum)
}
