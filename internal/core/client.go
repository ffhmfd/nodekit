package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"net/netip"
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
	legacy := map[string]bool{}
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
			p, e := strconv.ParseUint(addr[1], 16, 16)
			if e != nil {
				continue
			}
			legacy[fmt.Sprintf("%s:%d", strings.TrimSuffix(network, "6"), p)] = true
			if strings.HasPrefix(network, "udp") && f[3] != "07" {
				continue
			}
			address, e := procAddress(addr[0])
			if e == nil {
				found[fmt.Sprintf("%s/%s/%d", network, address, p)] = true
			}
		}
	}
	for _, endpoint := range cfg.ListenerEndpoints() {
		p := endpoint.Protocol
		networks := []string{"tcp"}
		if p.Type == "ss" {
			networks = []string{"tcp", "udp"}
		} else if p.Type == "tuic" || p.Type == "hysteria2" {
			networks = []string{"udp"}
		}
		for _, n := range networks {
			if endpoint.Family == "legacy" {
				if !legacy[fmt.Sprintf("%s:%d", n, p.Port)] {
					return fmt.Errorf("core listener unavailable: %s %s/%d", p.Type, n, p.Port)
				}
				continue
			}
			network := n
			if endpoint.Family == "ipv6" {
				network += "6"
			}
			if !found[fmt.Sprintf("%s/%s/%d", network, endpoint.Address, p.Port)] {
				return fmt.Errorf("core listener unavailable: %s %s %s", endpoint.Name, network, net.JoinHostPort(endpoint.Address, strconv.Itoa(p.Port)))
			}
		}
	}
	return nil
}

// Linux prints each address as native-endian 32-bit words, including tcp6/udp6.
// Decoding the entire IPv6 value as network-order hex reverses every word on
// little-endian hosts and can mistake a different address for the listener.
func procAddress(s string) (netip.Addr, error) {
	if len(s) != 8 && len(s) != 32 {
		return netip.Addr{}, errors.New("invalid proc socket address length")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 8 {
		word, err := strconv.ParseUint(s[i:i+8], 16, 32)
		if err != nil {
			return netip.Addr{}, err
		}
		binary.NativeEndian.PutUint32(b[i/2:], uint32(word))
	}
	address, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, errors.New("invalid proc socket address")
	}
	return address, nil
}
