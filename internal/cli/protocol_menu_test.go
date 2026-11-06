package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"nodekit/internal/cloudflare"
	"nodekit/internal/httpapi"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/store"
	"nodekit/internal/terminal"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func runProtocolMenu(p paths, input string, deps ipv6Deps) (string, error) {
	var out bytes.Buffer
	s := terminal.New(strings.NewReader(input), &out)
	err := protocolMenu(context.Background(), p, s, &out, deps)
	return out.String(), err
}

func protocolRecord(t *testing.T, db *store.Store) store.Record {
	t.Helper()
	r, err := db.Load()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestProtocolMenuStatusAndActions(t *testing.T) {
	p, db, old := ipv6CLIFixture(t)
	initial := protocolRecord(t, db)
	for i, label := range []string{"VLESS", "SS2022", "TUIC", "HY2", "AnyTLS"} {
		t.Run(label, func(t *testing.T) {
			for _, action := range []struct {
				choice  string
				enabled bool
			}{{"2", false}, {"1", true}} {
				out, err := runProtocolMenu(p, fmt.Sprintf("%d\n%s\n0\n", i+1, action.choice), ipv6TestDeps())
				if err != nil {
					t.Fatal(err, out)
				}
				r := protocolRecord(t, db)
				if r.Config.Protocols[i].Enabled != action.enabled || !strings.Contains(out, "刷新订阅") {
					t.Fatal("enable/disable did not commit or lacks refresh advice", out)
				}
				state := "已停用"
				if action.enabled {
					state = "已启用"
				}
				if !strings.Contains(out, fmt.Sprintf("%d %s：%s，端口%d", i+1, label, state, r.Config.Protocols[i].Port)) {
					t.Fatal("status was not refreshed", out)
				}
			}
			port := 25441 + i
			out, err := runProtocolMenu(p, fmt.Sprintf("%d\n3\n%d\n0\n", i+1, port), ipv6TestDeps())
			if err != nil {
				t.Fatal(err, out)
			}
			r := protocolRecord(t, db)
			if r.Config.Protocols[i].Port != port || !strings.Contains(out, fmt.Sprintf("%s：已启用，端口%d", label, port)) {
				t.Fatal("port not committed/redisplayed", out)
			}
			before := r.Config.Protocols[i]
			out, err = runProtocolMenu(p, fmt.Sprintf("%d\n4\n0\n", i+1), ipv6TestDeps())
			if err != nil {
				t.Fatal(err, out)
			}
			after := protocolRecord(t, db).Config.Protocols[i]
			if after.Password == before.Password || after.UUID == before.UUID || after.Port != port || !after.Enabled {
				t.Fatal("credential rotation did not preserve other protocol settings")
			}
		})
	}
	r := protocolRecord(t, db)
	if r.Config.Token != old.Token || !reflect.DeepEqual(r.Meter, initial.Meter) || r.Config.Reality != old.Reality {
		t.Fatal("protocol management changed token, usage, or REALITY")
	}
	var out, errOut bytes.Buffer
	menu(context.Background(), p, strings.NewReader("8\n1\n2\n0\n0\n"), &out, &errOut)
	if errOut.Len() != 0 || protocolRecord(t, db).Config.Protocols[0].Enabled || !strings.Contains(out.String(), "选择协议") {
		t.Fatal("main menu 8 did not enter numeric protocol management", errOut.String(), out.String())
	}
}

func TestProtocolMenuInputAndNames(t *testing.T) {
	p, db, old := ipv6CLIFixture(t)
	checks := 0
	deps := ipv6TestDeps()
	deps.CheckPorts = func(model.Config, []platform.Binding) error { checks++; return nil }
	out, err := runProtocolMenu(p, "abc\n99\n-1\n1\nno\n7\n3\ntext\n-2\n65536\n1\n24442\n65535\n0\n", deps)
	if err != nil || checks != 1 || protocolRecord(t, db).Config.Protocols[0].Port != 65535 {
		t.Fatal("invalid input was submitted or valid retry failed", err, checks, out)
	}
	if !strings.Contains(out, "新端口（1024–65535，0返回）") || !strings.Contains(out, "请输入1024–65535的端口") {
		t.Fatal("port prompt must explain the supported minimum in Chinese", out)
	}
	// Names are read as one line; reserved/empty names retry before any commit.
	out, err = runProtocolMenu(p, "1\n5\n\nDIRECT\n我的  东京 REALITY\n0\n", deps)
	if err != nil || checks != 2 || protocolRecord(t, db).Config.Protocols[0].Name != "我的  东京 REALITY" {
		t.Fatal("full name lost spaces or invalid name committed", err, checks, out)
	}
	out, err = runProtocolMenu(p, "1\n6\n0\n", deps)
	r := protocolRecord(t, db)
	if err != nil || checks != 3 || r.Config.Protocols[0].Name != "" || r.Config.Token != old.Token || r.Meter.Upload != 123 {
		t.Fatal("restore automatic name failed", err, checks, out)
	}
	// Numbering follows the actual config list, not a hard-coded protocol map.
	c := r.Config.Clone()
	c.Protocols[0], c.Protocols[4] = c.Protocols[4], c.Protocols[0]
	if err := db.Update(func(r *store.Record) error { r.Config = c; return nil }); err != nil {
		t.Fatal(err)
	}
	out, err = runProtocolMenu(p, "1\n2\n0\n", deps)
	r = protocolRecord(t, db)
	if err != nil || r.Config.Protocols[0].Type != "anytls" || r.Config.Protocols[0].Enabled || !r.Config.Protocols[4].Enabled {
		t.Fatal("numbered selection ignored config order", err, out)
	}
}

func TestProtocolMenuReturnAndEOF(t *testing.T) {
	for _, tc := range []struct {
		input string
		eof   bool
	}{
		{"0\n", false}, {"1\n0\n0\n", false}, {"1\n3\n0\n0\n0\n", false}, {"1\n5\n0\n0\n0\n", false},
		{"", true}, {"1\n", true}, {"1\n3\n", true}, {"1\n5\n", true},
	} {
		t.Run(fmt.Sprintf("%q", tc.input), func(t *testing.T) {
			p, db, _ := ipv6CLIFixture(t)
			before := protocolRecord(t, db)
			_, err := runProtocolMenu(p, tc.input, ipv6TestDeps())
			if (tc.eof && !errors.Is(err, io.EOF)) || (!tc.eof && err != nil) {
				t.Fatal("wrong return/EOF", err)
			}
			if !reflect.DeepEqual(protocolRecord(t, db), before) {
				t.Fatal("unfinished input changed state")
			}
		})
	}
	p, db, _ := ipv6CLIFixture(t)
	before := protocolRecord(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	err := protocolMenu(ctx, p, terminal.New(strings.NewReader("1\n2\n"), &out), &out, ipv6TestDeps())
	if !errors.Is(err, terminal.ErrCanceled) && !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if !reflect.DeepEqual(protocolRecord(t, db), before) {
		t.Fatal("canceled operation committed")
	}
	var errOut bytes.Buffer
	if menu(context.Background(), p, strings.NewReader("8\n1\n3\n"), &out, &errOut) != 0 || errOut.Len() != 0 {
		t.Fatal("EOF did not exit normally", errOut.String())
	}
}

func TestProtocolMenuErrors(t *testing.T) {
	t.Run("occupied port", func(t *testing.T) {
		p, db, _ := ipv6CLIFixture(t)
		before := protocolRecord(t, db)
		occupied := errors.New("port occupied tcp4/25441")
		deps := ipv6TestDeps()
		deps.CheckPorts = func(model.Config, []platform.Binding) error { return occupied }
		out, err := runProtocolMenu(p, "1\n3\n25441\n1\n2\n0\n", deps)
		if !errors.Is(err, occupied) || strings.Contains(out, "刷新订阅") || !reflect.DeepEqual(protocolRecord(t, db), before) {
			t.Fatal("port error swallowed/retried or state changed", err, out)
		}
	})
	for _, mode := range []string{"read", "reject", "applied", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			p, db, _ := ipv6CLIFixture(t)
			before := protocolRecord(t, db)
			// Fault injection at the HTTP boundary keeps real admin validation and DB writes.
			p.Run += "-err"
			if err := os.MkdirAll(p.Run, 0700); err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("unix", filepath.Join(p.Run, "admin.sock"))
			if err != nil {
				t.Fatal(err)
			}
			var puts atomic.Int32
			admin := httpapi.Admin(editBackend{certBackend{db}})
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && (mode == "read" || (mode == "uncertain" && puts.Load() > 0)) {
					http.Error(w, "admin read failure", 503)
					return
				}
				if r.Method == "PUT" {
					puts.Add(1)
					if mode == "applied" {
						recorder := httptest.NewRecorder()
						admin.ServeHTTP(recorder, r)
						if recorder.Code != 204 {
							t.Errorf("fixture commit failed: %s", recorder.Body.String())
						}
						// The lightweight editBackend does not advance revisions as
						// the real manager does; model that before losing its reply.
						if err := db.Update(func(r *store.Record) error { r.Config.Revision++; return nil }); err != nil {
							t.Error(err)
						}
					}
					http.Error(w, "admin commit failure", 503)
					return
				}
				admin.ServeHTTP(w, r)
			})}
			go server.Serve(ln)
			t.Cleanup(func() { server.Close() })
			out, err := runProtocolMenu(p, "1\n2\n1\n4\n0\n", ipv6TestDeps())
			if err == nil || !strings.Contains(err.Error(), "admin ") || strings.Contains(out, "刷新订阅") {
				t.Fatal("admin failure lost or falsely successful", err, out)
			}
			wantPuts := int32(1)
			if mode == "read" {
				wantPuts = 0
			}
			if puts.Load() != wantPuts {
				t.Fatal("failed/uncertain commit retried", puts.Load())
			}
			if errors.Is(err, errConfigApplied) != (mode == "applied") || errors.Is(err, cloudflare.ErrUncertain) != (mode == "uncertain") {
				t.Fatal("commit outcome marker lost", err)
			}
			after := protocolRecord(t, db)
			if mode == "applied" {
				if after.Config.Protocols[0].Enabled {
					t.Fatal("fixture did not commit")
				}
			} else if !reflect.DeepEqual(after, before) {
				t.Fatal("failed operation changed DB")
			}
		})
	}
}

func TestProtocolMenuIPv6(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			p, db, c := ipv6CLIFixture(t)
			c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: enabled, Address: "2001:4860:4860::8888", Protocols: []string{"vless", "hysteria2"}, IPv4ListenAddresses: []string{"10.0.0.4", "127.0.0.1"}}
			if err := db.Update(func(r *store.Record) error { r.Config = c; return nil }); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{"2", "1", "3\n25441", "5\n东京 IPv6 共用", "4"} {
				out, err := runProtocolMenu(p, "1\n"+action+"\n0\n", ipv6TestDeps())
				if err != nil {
					t.Fatal(err, out)
				}
				r := protocolRecord(t, db)
				if !reflect.DeepEqual(r.Config.IPv6Nodes, c.IPv6Nodes) || r.Config.Token != c.Token || r.Meter.Upload != 123 {
					t.Fatal("original protocol action changed IPv6 selection/token/usage")
				}
				for _, hint := range []string{"IPv6", "共用端口、凭据及名称", "24", "不改变IPv6"} {
					if !strings.Contains(out, hint) {
						t.Fatal("missing IPv6 impact hint", hint, out)
					}
				}
				state := "已关闭（保留设置）"
				if enabled {
					state = "已启用"
				}
				if !strings.Contains(out, "IPv6节点："+state) {
					t.Fatal("incorrect IPv6 status", out)
				}
			}
		})
	}
}
