package cli

import (
	"bytes"
	"context"
	"testing"
)

func TestHelpAndInvalidCommand(t *testing.T) {
	for _, v := range []struct {
		args []string
		code int
	}{{[]string{"help"}, 0}, {[]string{"no-such-command"}, 2}} {
		var out, err bytes.Buffer
		if code := Run(context.Background(), v.args, bytes.NewBuffer(nil), &out, &err); code != v.code {
			t.Fatalf("code=%d want=%d stderr=%s", code, v.code, err.String())
		}
	}
}
func TestMenuEOF(t *testing.T) {
	var out, err bytes.Buffer
	if c := Run(context.Background(), nil, bytes.NewBuffer(nil), &out, &err); c != 0 {
		t.Fatal(c, err.String())
	}
}

func TestMenuUpgradeDispatchesCollectedArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	input := bytes.NewBufferString("11\n/a release.tar.gz\n0123\n0\n")
	code := Run(context.Background(), []string{"--root", t.TempDir()}, input, &out, &errOut)
	if code != 0 || errOut.Len() == 0 {
		t.Fatal("upgrade menu did not dispatch command", code, out.String())
	}
}
