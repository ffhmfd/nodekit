package cli

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"reflect"
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
	p, db, _ := ipv6CLIFixture(t)
	before := protocolRecord(t, db)
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
	cmd.Env = append(os.Environ(), "NODEKIT_MENU_CHILD=1", "NODEKIT_MENU_ROOT="+p.Root)
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
	for _, portInput := range []bool{false, true} {
		master.Write([]byte("8\n"))
		wait("选择协议")
		if portInput {
			master.Write([]byte("1\n"))
			wait("选择操作")
			master.Write([]byte("3\n"))
			wait("新端口")
		}
		master.Write([]byte("123\x03"))
		wait("请输入编号")
		if !reflect.DeepEqual(protocolRecord(t, db), before) {
			t.Fatal("protocol menu cancellation changed configuration")
		}
	}
	for i := 0; i < 2; i++ {
		master.Write([]byte("5\n"))
		wait("输入值")
		master.Write([]byte("unsaved\x03"))
		wait("请输入编号")
	}
	master.Write([]byte("24\n"))
	wait("请选择")
	master.Write([]byte("unsaved\x03"))
	wait("请输入编号")
	master.Write([]byte("24\n"))
	wait("请选择")
	master.Write([]byte("0\n"))
	wait("请输入编号")
	master.Write([]byte("99\n"))
	// The invalid-choice message is still inside the action's signal scope.
	// Wait for the next input scope before testing main-menu Ctrl+C exit.
	wait("请输入编号")
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
