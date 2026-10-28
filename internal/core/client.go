package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"nodekit/internal/meter"
	"nodekit/internal/model"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Client struct{ Socket, WorkDir, Binary string }

func (c *Client) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	var r io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, e
		}
		r = bytes.NewReader(b)
	}
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, e := http.NewRequestWithContext(ctx, method, "http://core"+path, r)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := hc.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if e != nil {
		return nil, e
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("core API returned %d", res.StatusCode)
	}
	return b, nil
}
func (c *Client) identity(ctx context.Context) (int, string, time.Time, error) {
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	if e != nil {
		return 0, "", time.Time{}, e
	}
	defer conn.Close()
	u := conn.(*net.UnixConn)
	raw, e := u.SyscallConn()
	if e != nil {
		return 0, "", time.Time{}, e
	}
	var cred *unix.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil {
		return 0, "", time.Time{}, e
	}
	if inner != nil {
		return 0, "", time.Time{}, inner
	}
	pid := int(cred.Pid)
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return 0, "", time.Time{}, e
	}
	end := strings.LastIndex(string(b), ") ")
	if end < 0 {
		return 0, "", time.Time{}, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(b)[end+2:])
	if len(fields) < 20 {
		return 0, "", time.Time{}, errors.New("short process stat")
	}
	ticks, e := strconv.ParseInt(fields[19], 10, 64)
	if e != nil {
		return 0, "", time.Time{}, e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return 0, "", time.Time{}, e
	}
	stat, e := os.ReadFile("/proc/stat")
	if e != nil {
		return 0, "", time.Time{}, e
	}
	var btime int64
	for _, line := range strings.Split(string(stat), "\n") {
		if strings.HasPrefix(line, "btime ") {
			btime, e = strconv.ParseInt(strings.TrimPrefix(line, "btime "), 10, 64)
			if e != nil {
				return 0, "", time.Time{}, e
			}
		}
	}
	hzBytes, e := exec.CommandContext(ctx, "getconf", "CLK_TCK").Output()
	if e != nil {
		return 0, "", time.Time{}, e
	}
	hz, e := strconv.ParseInt(strings.TrimSpace(string(hzBytes)), 10, 64)
	if e != nil || hz <= 0 {
		return 0, "", time.Time{}, errors.New("invalid CLK_TCK")
	}
	return pid, fmt.Sprintf("%s:%d:%d", strings.TrimSpace(string(boot)), pid, ticks), time.Unix(btime+ticks/hz, 0).UTC(), nil
}
func (c *Client) Snapshot(ctx context.Context) (meter.Sample, error) {
	_, epoch, start, e := c.identity(ctx)
	if e != nil {
		return meter.Sample{}, e
	}
	b, e := c.request(ctx, "GET", "/connections", nil)
	if e != nil {
		return meter.Sample{}, e
	}
	var counts struct {
		Upload   *int64 `json:"uploadTotal"`
		Download *int64 `json:"downloadTotal"`
	}
	if e = json.Unmarshal(b, &counts); e != nil {
		return meter.Sample{}, e
	}
	if counts.Upload == nil || counts.Download == nil || *counts.Upload < 0 || *counts.Download < 0 {
		return meter.Sample{}, errors.New("invalid core counters")
	}
	_, after, _, e := c.identity(ctx)
	if e != nil {
		return meter.Sample{}, e
	}
	if after != epoch {
		return meter.Sample{}, errors.New("core restarted during sampling")
	}
	return meter.Sample{Epoch: epoch, StartedAt: start, At: time.Now().UTC(), Upload: *counts.Upload, Download: *counts.Download}, nil
}
func (c *Client) Check(ctx context.Context, b []byte) error {
	if e := os.MkdirAll(c.WorkDir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(c.WorkDir, "check-*.yaml")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	o, e := exec.CommandContext(ctx, c.Binary, "-d", c.WorkDir, "-f", f.Name(), "-t").CombinedOutput()
	if e != nil {
		return fmt.Errorf("core validation failed: %w (%s)", e, strings.TrimSpace(string(o)))
	}
	return nil
}
func (c *Client) Apply(ctx context.Context, path string) error {
	_, e := c.request(ctx, "PUT", "/configs?force=true", map[string]string{"path": path})
	return e
}
func (c *Client) Health(ctx context.Context, cfg model.Config) error {
	pid, _, _, e := c.identity(ctx)
	if e != nil {
		return e
	}
	entries, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if e != nil {
		return e
	}
	inodes := map[string]bool{}
	for _, f := range entries {
		target, e := os.Readlink(filepath.Join(fmt.Sprintf("/proc/%d/fd", pid), f.Name()))
		if e == nil && strings.HasPrefix(target, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	found := map[string]bool{}
	for _, network := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, e := os.ReadFile("/proc/net/" + network)
		if e != nil {
			return e
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || !inodes[f[9]] {
				continue
			}
			if strings.HasPrefix(network, "tcp") && f[3] != "0A" {
				continue
			}
			addr := strings.Split(f[1], ":")
			if len(addr) != 2 {
				continue
			}
			p, e := strconv.ParseInt(addr[1], 16, 32)
			if e == nil {
				found[fmt.Sprintf("%s:%d", strings.TrimSuffix(network, "6"), p)] = true
			}
		}
	}
	for _, p := range cfg.Protocols {
		if !p.Enabled {
			continue
		}
		networks := []string{"tcp"}
		if p.Type == "ss" {
			networks = []string{"tcp", "udp"}
		} else if p.Type == "tuic" || p.Type == "hysteria2" {
			networks = []string{"udp"}
		}
		for _, n := range networks {
			if !found[fmt.Sprintf("%s:%d", n, p.Port)] {
				return fmt.Errorf("core listener unavailable: %s %s/%d", p.Type, n, p.Port)
			}
		}
	}
	return nil
}
