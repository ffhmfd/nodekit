package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRoutingOfflineCoreExecutable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("offline core wrapper is Linux-only")
	}
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "fixture-core")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, tc := range []struct{ name, selection string }{
		{"absolute-path", bin},
		{"bare-PATH", "fixture-core"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NODEKIT_CORE_BIN", tc.selection)
			cleanup, err := routingOfflineCore()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cleanup)
			wrapper := os.Getenv("NODEKIT_CORE_BIN")
			home := filepath.Join(t.TempDir(), "core home")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, wrapper, "-d", home, "argument with spaces").CombinedOutput()
			if err != nil {
				t.Fatalf("execute offline core wrapper: %v (%s)", err, output)
			}
			if want := "-d\n" + home + "\nargument with spaces\n"; string(output) != want {
				t.Fatalf("forwarded arguments = %q, want %q", output, want)
			}
			for _, name := range []string{"GeoSite.dat", "Country.mmdb"} {
				info, err := os.Stat(filepath.Join(home, name))
				if err != nil {
					t.Fatal(err)
				}
				if info.Size() == 0 {
					t.Fatalf("empty seeded fixture %s", name)
				}
			}
			cleanup()
			if _, err := os.Stat(filepath.Dir(wrapper)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("wrapper fixture directory remains after cleanup: %v", err)
			}
		})
	}
}

func TestRoutingOfflineCoreUnknownExecutable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("offline core wrapper is Linux-only")
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("NODEKIT_CORE_BIN", "nodekit-no-such-core")
	cleanup, err := routingOfflineCore()
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("unknown executable error = %v, want executable not found", err)
	}
	if !strings.Contains(err.Error(), "NODEKIT_CORE_BIN") || !strings.Contains(err.Error(), "nodekit-no-such-core") {
		t.Fatalf("unknown executable error lacks selection context: %v", err)
	}
}
