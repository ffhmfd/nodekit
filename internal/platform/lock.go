package platform

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

var ErrLocked = errors.New("another operation is already running")

// AcquireLock rejects symlinks and holds a process lock until Close.
func AcquireLock(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("invalid lock file")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		if errors.Is(e, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, e
	}
	return f, nil
}
