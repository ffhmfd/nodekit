// Package terminal owns cancellable terminal input, not process signals.
package terminal

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
	"sync"
)

var ErrCanceled = errors.New("input canceled")

type Session struct {
	reader *bufio.Reader
	file   *os.File
	out    io.Writer
	mu     sync.Mutex
}

func New(in io.Reader, out io.Writer) *Session {
	s := &Session{reader: bufio.NewReader(in), out: out}
	if f, ok := in.(*os.File); ok {
		if _, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err == nil {
			s.file = f
		}
	}
	return s
}
func (s *Session) IsTTY() bool { return s.file != nil }

func (s *Session) Printf(format string, args ...any) { fmt.Fprintf(s.out, format, args...) }

type sessionKey struct{}

func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}
func FromContext(ctx context.Context) *Session { s, _ := ctx.Value(sessionKey{}).(*Session); return s }

func (s *Session) ReadLine(ctx context.Context, label string, secret bool) (text string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return "", ErrCanceled
	}
	if s.file == nil {
		if secret {
			return "", errors.New("hidden Token input requires a terminal; use --token-file")
		}
		fmt.Fprint(s.out, label)
		line, e := s.reader.ReadString('\n')
		if ctx.Err() != nil {
			return "", ErrCanceled
		}
		if e != nil && len(line) == 0 {
			return "", e
		}
		return strings.TrimSpace(line), nil
	}
	fd := int(s.file.Fd())
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if e != nil {
		return "", e
	}
	if _, e = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags|unix.O_NONBLOCK); e != nil {
		return "", e
	}
	defer func() {
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); e != nil {
			err = errors.Join(err, e)
		}
	}()
	original, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	if e != nil {
		return "", e
	}
	mode := *original
	mode.Lflag |= unix.ICANON | unix.ISIG
	mode.Lflag &^= unix.NOFLSH
	if secret {
		mode.Lflag &^= unix.ECHO | unix.ECHONL
	}
	if e = unix.IoctlSetTermios(fd, unix.TCSETS, &mode); e != nil {
		return "", e
	}
	defer func() {
		request := uint(unix.TCSETS)
		if errors.Is(err, ErrCanceled) {
			request = unix.TCSETSF
		}
		if e := unix.IoctlSetTermios(fd, request, original); e != nil {
			err = errors.Join(err, e)
		}
		if secret || errors.Is(err, ErrCanceled) {
			fmt.Fprintln(s.out)
		}
	}()
	fmt.Fprint(s.out, label)
	var line strings.Builder
	for {
		if ctx.Err() != nil {
			return "", ErrCanceled
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, e = unix.Poll(poll, 50)
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return "", e
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return "", io.EOF
		}
		if poll[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			continue
		}
		var b [1]byte
		n, e := unix.Read(fd, b[:])
		if e == unix.EINTR || e == unix.EAGAIN {
			continue
		}
		if e != nil {
			return "", e
		}
		if n == 0 {
			return "", io.EOF
		}
		if b[0] == '\n' {
			return strings.TrimSpace(line.String()), nil
		}
		line.WriteByte(b[0])
		if line.Len() > 8192 {
			return "", errors.New("input line too long")
		}
	}
}
