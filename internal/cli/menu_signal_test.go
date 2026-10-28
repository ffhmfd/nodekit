package cli

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInteractiveMenuProcess(t *testing.T) {
	if os.Getenv("NODEKIT_MENU_CHILD") != "1" {
		return
	}
	os.Exit(Run(context.Background(), []string{"--root", os.Getenv("NODEKIT_MENU_ROOT")}, os.Stdin, os.Stdout, os.Stderr))
}

func TestCompletedOperationIsNotReportedAsCanceled(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt
	err := interrupted(context.Background(), signals, func(ctx context.Context) error { <-ctx.Done(); return nil })
	if err != nil {
		t.Fatal("completed commit was relabeled as canceled", err)
	}
}

func TestMenuCtrlCReturnsThenAcceptsNewInput(t *testing.T) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "master")
	defer master.Close()
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
	defer slave.Close()
	self, _ := os.Executable()
	cmd := exec.Command(self, "-test.run=^TestInteractiveMenuProcess$")
	cmd.Env = append(os.Environ(), "NODEKIT_MENU_CHILD=1", "NODEKIT_MENU_ROOT="+t.TempDir())
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			<-done
		}
	}()
	wait := func(want string) {
		t.Helper()
		text := ""
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, err := unix.Poll(fds, 100)
			if err != nil && err != unix.EINTR {
				t.Fatal(err)
			}
			if fds[0].Revents&unix.POLLIN != 0 {
				b := make([]byte, 4096)
				n, err := unix.Read(fd, b)
				if err != nil {
					t.Fatal(err)
				}
				text += string(b[:n])
				if strings.Contains(text, want) {
					return
				}
			}
		}
		t.Fatalf("missing %q in %q", want, text)
	}
	wait("请输入编号")
	for i := 0; i < 2; i++ {
		master.Write([]byte("5\n"))
		wait("输入值")
		master.Write([]byte("unsaved\x03"))
		wait("请输入编号")
	}
	master.Write([]byte("99\n"))
	wait("无效选项")
	master.Write([]byte{3})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("main menu interrupt did not exit")
	}
}
