package terminal

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"testing"
	"time"
)

func ttyPair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "master")
	t.Cleanup(func() { master.Close() })
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

func TestTTYCancelRestoresEchoAndDiscardsInput(t *testing.T) {
	master, slave := ttyPair(t)
	s := New(slave, slave)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.ReadLine(ctx, "Token: ", true); done <- err }()
	buf := make([]byte, 128)
	n, err := master.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "Token:") {
		t.Fatal("missing secret prompt", err)
	}
	mode, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || mode.Lflag&unix.ECHO != 0 {
		t.Fatal("secret input echoed")
	}
	master.Write([]byte("partial-secret"))
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrCanceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked terminal input did not cancel")
	}
	mode, err = unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || mode.Lflag&unix.ECHO == 0 {
		t.Fatal("echo not restored")
	}
	line := make(chan string, 1)
	go func() { text, _ := s.ReadLine(context.Background(), "Next: ", false); line <- text }()
	master.Read(buf)
	master.Write([]byte("fresh\n"))
	select {
	case got := <-line:
		if got != "fresh" {
			t.Fatal("stale input", got)
		}
	case <-time.After(time.Second):
		t.Fatal("next input blocked")
	}
}

func TestSecretInputRequiresTTY(t *testing.T) {
	s := New(strings.NewReader("token\n"), os.Stdout)
	if _, err := s.ReadLine(context.Background(), "", true); err == nil {
		t.Fatal("secret accepted through non-TTY prompt")
	}
}

func TestTTYReadCannotBlockAfterReadinessIsFlushed(t *testing.T) {
	master, slave := ttyPair(t)
	fd := int(slave.Fd())
	before, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := New(slave, slave).ReadLine(ctx, "secret:", true); done <- err }()
	b := make([]byte, 128)
	master.Read(b)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Error("TTY read can block after SIGINT flushes poll readiness", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrCanceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
	after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || after != before {
		t.Fatal("descriptor flags not restored", err)
	}
}
