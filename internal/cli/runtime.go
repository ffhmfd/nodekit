package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"nodekit/internal/cert"
	"nodekit/internal/core"
	"nodekit/internal/httpapi"
	"nodekit/internal/manager"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/render"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type paths struct{ Root, Etc, Data, Run, Opt, Core string }

func makePaths(root, coreBin string) paths {
	p := paths{Root: root, Etc: filepath.Join(root, "etc/nodekit"), Data: filepath.Join(root, "var/lib/nodekit"), Run: filepath.Join(root, "run/nodekit"), Opt: filepath.Join(root, "opt/nodekit")}
	p.Core = coreBin
	if p.Core == "" {
		p.Core = filepath.Join(p.Opt, "current/mihomo")
	}
	return p
}
func (p paths) render() render.Paths {
	return render.Paths{Socket: filepath.Join(p.Run, "core.sock"), WorkDir: p.Data}
}

type runtimeConfig struct {
	Email        string `json:"email"`
	TokenFile    string `json:"token_file"`
	DirectoryURL string `json:"directory_url"`
	Firewall     string `json:"firewall"`
}

func (p paths) runtime() (runtimeConfig, error) {
	var r runtimeConfig
	b, e := os.ReadFile(filepath.Join(p.Etc, "runtime.json"))
	if e != nil {
		return r, e
	}
	e = json.Unmarshal(b, &r)
	return r, e
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return platform.WritePrivate(path, append(b, '\n'))
}
func (p paths) db() (*store.Store, error) { return store.Open(filepath.Join(p.Data, "state.db")) }
func (p paths) admin(ctx context.Context, method, path string, body any, out any) error {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(p.Run, "admin.sock"))
	}}
	defer tr.CloseIdleConnections()
	timeout := 60 * time.Second
	if path == "/cert/renew" {
		timeout = 11 * time.Minute
	}
	return callHTTP(ctx, &http.Client{Transport: tr, Timeout: timeout}, method, "http://admin"+path, body, out)
}
func serve(ctx context.Context, p paths) error {
	lock, e := platform.AcquireLock(filepath.Join(p.Data, "manager.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	rt, e := p.runtime()
	if e != nil {
		return e
	}
	db, e := p.db()
	if e != nil {
		return e
	}
	defer db.Close()
	r, e := db.Load()
	if e != nil {
		return e
	}
	if e = r.Config.Validate(); e != nil {
		return e
	}
	if r.Config.CertID == "" {
		return errors.New("certificate not ready; run init or cert renew")
	}
	if e = os.MkdirAll(p.Run, 0700); e != nil {
		return e
	}
	client := &core.Client{Socket: p.render().Socket, WorkDir: p.Data, Binary: p.Core}
	mgr, e := manager.New(db, client, nil, p.render())
	if e != nil {
		return e
	}
	if e = mgr.Recover(ctx); e != nil {
		return e
	}
	adminPath := filepath.Join(p.Run, "admin.sock")
	if conn, e := net.DialTimeout("unix", adminPath, time.Second); e == nil {
		conn.Close()
		return errors.New("manager already running")
	}
	if info, e := os.Lstat(adminPath); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing non-socket admin path")
		}
		if e = os.Remove(adminPath); e != nil {
			return e
		}
	}
	adminLn, e := net.Listen("unix", adminPath)
	if e != nil {
		return e
	}
	defer adminLn.Close()
	defer os.Remove(adminPath)
	if e = os.Chmod(adminPath, 0600); e != nil {
		return e
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		current, e := db.Load()
		if e != nil {
			return nil, e
		}
		b, e := cert.Load(filepath.Join(p.Data, "certs"), current.Config.CertID)
		if e != nil {
			return nil, e
		}
		if e = cert.Validate(b, current.Config.Domain, time.Now()); e != nil {
			return nil, e
		}
		pair, e := tls.X509KeyPair(b.Certificate, b.PrivateKey)
		return &pair, e
	}}
	bind := "0.0.0.0"
	if r.Config.IPv6 {
		bind = "::"
	}
	publicLn, e := tls.Listen("tcp", net.JoinHostPort(bind, fmt.Sprint(r.Config.SubscriptionPort)), tlsConfig)
	if e != nil {
		return e
	}
	defer publicLn.Close()
	certificates := &certificateController{db: db, backend: mgr, paths: p, runtime: rt}
	backend := managedBackend{Manager: mgr, certificates: certificates}
	admin := &http.Server{Handler: httpapi.Admin(backend), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 11 * time.Minute, IdleTimeout: 30 * time.Second}
	public := &http.Server{Handler: httpapi.Subscription(mgr), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 3)
	var workers sync.WaitGroup
	servePublic := func(ln net.Listener) {
		err := public.Serve(ln)
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			select {
			case errs <- err:
			case <-ctx.Done():
			}
		}
	}
	mgr.PrepareListener = func(old, next model.Config) (func(), func(), error) {
		if old.SubscriptionPort == next.SubscriptionPort && old.IPv6 == next.IPv6 {
			return func() {}, func() {}, nil
		}
		host := "0.0.0.0"
		if next.IPv6 {
			host = "::"
		}
		ln, err := tls.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(next.SubscriptionPort)), tlsConfig)
		if err != nil {
			return nil, nil, err
		}
		go servePublic(ln)
		return func() { previous := publicLn; publicLn = ln; _ = previous.Close() }, func() { _ = ln.Close() }, nil
	}
	go func() { errs <- admin.Serve(adminLn) }()
	go servePublic(publicLn)
	workers.Add(2)
	go func() { defer workers.Done(); errs <- mgr.Run(ctx) }()
	go func() { defer workers.Done(); certificates.run(ctx) }()
	select {
	case <-ctx.Done():
		e = nil
	case e = <-errs:
		if errors.Is(e, http.ErrServerClosed) {
			e = nil
		}
	}
	cancel()
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = admin.Shutdown(shutdown)
	_ = public.Shutdown(shutdown)
	workers.Wait()
	return e
}
