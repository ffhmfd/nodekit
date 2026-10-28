package platform

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func privateParent(path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !ok || int(st.Uid) != os.Geteuid() {
		return errors.New("untrusted private directory")
	}
	return nil
}

func Owned(dir string) error {
	info, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid owned directory")
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	f, e := root.OpenFile(".nodekit-owned", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e = f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > 64 {
		return errors.New("invalid ownership marker")
	}
	b, e := io.ReadAll(io.LimitReader(f, 64))
	if e != nil {
		return e
	}
	if string(b) != "nodekit-v1\n" {
		return errors.New("directory is not owned by NodeKit")
	}
	return nil
}
func ReadPrivate(path string) ([]byte, error) {
	parent := filepath.Dir(path)
	if e := privateParent(parent); e != nil {
		return nil, e
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	f, e := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ok || int(st.Uid) != os.Geteuid() || info.Size() > 16<<20 {
		return nil, errors.New("untrusted private file")
	}
	return io.ReadAll(f)
}
func WritePrivate(path string, b []byte) error {
	parent := filepath.Dir(path)
	if e := os.MkdirAll(parent, 0700); e != nil {
		return e
	}
	if e := privateParent(parent); e != nil {
		return e
	}
	return RestoreAtomic(parent, filepath.Base(path), b, os.Geteuid(), os.Getegid())
}

// RestoreAtomic never opens the destination: rename replaces a hostile symlink
// instead of following it. Ownership is set on the newly-created descriptor.
func RestoreAtomic(dir, name string, data []byte, uid, gid int) error {
	if name == "." || name == ".." || filepath.Base(name) != name {
		return errors.New("invalid restore name")
	}
	info, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid restore directory")
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return e
	}
	tmp := ".restore-" + hex.EncodeToString(random)
	f, e := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(tmp)
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Chown(uid, gid); e != nil {
		f.Close()
		return e
	}
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = root.Rename(tmp, name); e != nil {
		return e
	}
	parent, e := root.Open(".")
	if e != nil {
		return e
	}
	defer parent.Close()
	return parent.Sync()
}
