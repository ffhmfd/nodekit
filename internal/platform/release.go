package platform

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

type Release struct {
	Version     string `json:"version"`
	Arch        string `json:"arch"`
	CoreVersion string `json:"core_version"`
	Schema      int    `json:"schema"`
}

func ExtractRelease(archive, dest, expected string) (Release, error) {
	var r Release
	digest, e := hex.DecodeString(expected)
	if e != nil || len(digest) != 32 {
		return r, errors.New("valid SHA256 required")
	}
	f, e := os.Open(archive)
	if e != nil {
		return r, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 200<<20))
	if e != nil || n >= 200<<20 {
		return r, errors.New("archive too large or unreadable")
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return r, errors.New("release checksum mismatch")
	}
	if _, e = f.Seek(0, 0); e != nil {
		return r, e
	}
	gz, e := gzip.NewReader(f)
	if e != nil {
		return r, e
	}
	defer gz.Close()
	if _, e = os.Lstat(dest); !errors.Is(e, os.ErrNotExist) {
		return r, errors.New("release destination already exists")
	}
	if e = os.MkdirAll(dest, 0700); e != nil {
		return r, e
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dest)
		}
	}()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return r, e
		}
		if hdr.Typeflag != tar.TypeReg || (hdr.Name != "nodekit" && hdr.Name != "mihomo" && hdr.Name != "release.json") || seen[hdr.Name] || hdr.Size < 0 || hdr.Size > 128<<20 {
			return r, errors.New("unsafe release archive entry")
		}
		seen[hdr.Name] = true
		mode := os.FileMode(0755)
		if hdr.Name == "release.json" {
			mode = 0644
		}
		out, e := os.OpenFile(filepath.Join(dest, hdr.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if e != nil {
			return r, e
		}
		_, e = io.CopyN(out, tr, hdr.Size)
		closeErr := out.Close()
		if e != nil {
			return r, e
		}
		if closeErr != nil {
			return r, closeErr
		}
		if e = os.Chmod(filepath.Join(dest, hdr.Name), mode); e != nil {
			return r, e
		}
	}
	if len(seen) != 3 {
		return r, errors.New("release missing files")
	}
	b, e := os.ReadFile(filepath.Join(dest, "release.json"))
	if e != nil {
		return r, e
	}
	if e = json.Unmarshal(b, &r); e != nil {
		return r, e
	}
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$`).MatchString(r.Version) || r.Arch != runtime.GOARCH || r.Schema != 1 || r.CoreVersion != "v1.19.33" {
		return r, errors.New("incompatible release metadata")
	}
	ok = true
	return r, nil
}
