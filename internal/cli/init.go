package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"nodekit/internal/cert"
	"nodekit/internal/cloudflare"
	"nodekit/internal/core"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/render"
	"nodekit/internal/store"
	"nodekit/internal/terminal"
	"os"
	"path/filepath"
	"time"
)

func initialize(ctx context.Context, p paths, args []string, in io.Reader, out io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(out)
	configFile := fs.String("config", "", "configuration JSON")
	domain := fs.String("domain", "", "subscription and certificate domain")
	subscriptionMode := fs.String("subscription-mode", "", "direct or cloudflare")
	subscriptionPort := fs.Int("subscription-port", 0, "HTTPS subscription port")
	ipv6 := fs.Bool("ipv6", false, "enable IPv6")
	address := fs.String("address", "", "public IP address")
	managedDNS := fs.Bool("managed-dns", false, "manage this node's Cloudflare DNS record")
	dnsZoneID := fs.String("dns-zone", "", "Cloudflare zone ID (otherwise discover by domain)")
	adoptDNS := fs.Bool("adopt-dns", false, "explicitly adopt the existing dedicated DNS record")
	displayName := fs.String("name", "", "node display hostname")
	country := fs.String("country", "", "two-letter flag country code")
	realitySNI := fs.String("reality-sni", "", "REALITY server name and target domain")
	email := fs.String("email", "", "ACME email")
	token := fs.String("token-file", "", "Cloudflare token file")
	certPath := fs.String("certificate", "", "import certificate")
	keyPath := fs.String("key", "", "import key")
	dry := fs.Bool("dry-run", false, "write private bootstrap configuration only")
	noService := fs.Bool("no-service", false, "prepare without systemd start")
	firewall := fs.String("firewall", "manual", "manual or auto")
	staging := fs.Bool("staging", false, "use ACME staging")
	if e := fs.Parse(args); e != nil {
		return e
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if *firewall != "manual" && *firewall != "auto" {
		return errors.New("firewall must be manual or auto")
	}
	bootstrap := filepath.Join(p.Etc, "bootstrap.json")
	if _, e := os.Stat(filepath.Join(p.Data, "state.db")); e == nil {
		if p.Root == "/" {
			if m, err := loadHost(p); err == nil && m.InitPhase != "ready" {
				mode := ""
				if explicit["firewall"] {
					mode = *firewall
				}
				return resumeWithFirewall(ctx, p, mode)
			}
		}
		return errors.New("已有配置，请使用 config/protocol 命令；重装请使用恢复流程")
	}
	stage := "参数校验"
	journal := false
	advance := func(next string) error {
		stage = next
		if journal {
			return saveInstallProgress(p, stage, false)
		}
		return nil
	}
	defer func() {
		if resultErr != nil && !*dry {
			resultErr = describeInstallFailure(p, stage, resultErr)
		}
	}()
	if *dry {
		if _, e := os.Stat(bootstrap); e == nil {
			return errors.New("已有 bootstrap.json，拒绝覆盖凭据")
		}
	}
	c, e := model.New()
	if e != nil {
		return e
	}
	if *configFile != "" {
		b, e := os.ReadFile(*configFile)
		if e != nil {
			return e
		}
		if e = json.Unmarshal(b, &c); e != nil {
			return e
		}
	} else if *domain == "" {
		session := terminal.FromContext(ctx)
		if session == nil {
			session = terminal.New(in, out)
		}
		prompt := func(label string) (string, error) {
			return session.ReadLine(ctx, label, false)
		}
		if !explicit["subscription-mode"] {
			*subscriptionMode, e = prompt("订阅模式 direct（灰云）/cloudflare（橙云），默认 direct: ")
			if e != nil {
				return e
			}
		}
		c.Domain, e = prompt("订阅/证书子域名: ")
		if e != nil {
			return e
		}
		c.Address, e = prompt("VPS 公网 IP: ")
		if e != nil {
			return e
		}
		if *email == "" {
			*email, e = prompt("ACME 邮箱: ")
			if e != nil {
				return e
			}
		}
		if *token == "" {
			*token, e = prompt("Cloudflare Token 文件路径: ")
			if e != nil {
				return e
			}
		}
		quota, e := prompt("流量额度（如 500GB）: ")
		if e != nil {
			return e
		}
		c.Quota, e = model.ParseBytes(quota)
		if e != nil {
			return e
		}
		expiry, e := prompt("到期北京时间（YYYY-MM-DD HH:mm，空为不设置）: ")
		if e != nil {
			return e
		}
		if expiry != "" {
			v, e := model.ParseExpiry(expiry)
			if e != nil {
				return e
			}
			c.Expiry = &v
		}
	}
	if *domain != "" {
		c.Domain = *domain
	}
	if *address != "" {
		c.Address = *address
	}
	if explicit["ipv6"] {
		c.IPv6 = *ipv6
	}
	if *subscriptionMode != "" {
		c.SubscriptionMode = *subscriptionMode
	}
	if explicit["subscription-mode"] && *subscriptionMode == "" {
		return errors.New("subscription mode must be direct or cloudflare")
	}
	if explicit["subscription-port"] {
		c.SubscriptionPort = *subscriptionPort
	} else if *configFile == "" && c.EffectiveSubscriptionMode() == "cloudflare" {
		c.SubscriptionPort = 8443
	}
	if *managedDNS {
		c.ManagedDNS = true
	}
	if *configFile == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "NodeKit"
		}
		if *displayName != "" {
			host = *displayName
		}
		if e = c.SetDisplayDefaults(host, *country); e != nil {
			return e
		}
	} else {
		if *displayName != "" {
			c.Name = *displayName
		}
		if explicit["country"] {
			c.CountryCode = *country
		}
	}
	if *realitySNI != "" {
		if e = c.SetRealityServerName(*realitySNI); e != nil {
			return e
		}
	}
	if e = c.Validate(); e != nil {
		return e
	}
	if !*dry {
		stage = "防火墙预检"
		if e = checkInstallFirewall(ctx, c, *firewall); e != nil {
			rememberPreflightFailure(p)
			return e
		}
	}
	stage = "准备安装目录"
	for _, dir := range []string{p.Etc, p.Data, p.Run, p.Opt} {
		if e = platform.Claim(dir); e != nil {
			return e
		}
	}
	if *dry {
		if e = writeJSON(bootstrap, c); e != nil {
			return e
		}
		fmt.Fprintln(out, "已生成私有配置:", bootstrap, "；未启动节点或修改防火墙")
		return nil
	}
	var host hostManifest
	lock, e := operationLock(p)
	if e != nil {
		return e
	}
	defer lock.Close()
	journal = true
	if e = advance("系统环境检查"); e != nil {
		return e
	}
	if c.ManagedDNS && os.Geteuid() != 0 {
		return errors.New("managed DNS initialization requires root")
	}
	if p.Root == "/" {
		if os.Geteuid() != 0 {
			return errors.New("系统安装需要 root")
		}
		if _, e = platform.Probe(ctx); e != nil {
			return e
		}
		host, e = preflightHost(ctx, p)
		if e != nil {
			return e
		}
	}
	if p.Root != "/" && c.ManagedDNS {
		host, e = loadHost(p)
		if errors.Is(e, os.ErrNotExist) {
			host = hostManifest{UID: os.Geteuid(), GID: os.Getegid(), Files: map[string]string{}, InitPhase: "prepared"}
			e = saveHost(p, host)
		}
		if e != nil {
			return e
		}
	}
	if e = advance("端口检查"); e != nil {
		return e
	}
	if e = platform.CheckPorts(c, nil); e != nil {
		return e
	}
	rt := runtimeConfig{Email: *email, Firewall: *firewall}
	if *staging {
		rt.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	if e = advance("保存凭据与运行配置"); e != nil {
		return e
	}
	if *token != "" {
		info, e := os.Stat(*token)
		if e != nil {
			return e
		}
		if info.Mode().Perm()&0007 != 0 {
			return errors.New("Token 文件不能对其他用户开放")
		}
		b, e := os.ReadFile(*token)
		if e != nil {
			return e
		}
		if c.ManagedDNS {
			standard := filepath.Join(p.Root, "root/nodekit-cloudflare.token")
			if e = platform.WritePrivate(standard, b); e != nil {
				return e
			}
			host.TokenSource = *token
		}
		rt.TokenFile = filepath.Join(p.Etc, "cloudflare.token")
		if e = platform.WritePrivate(rt.TokenFile, b); e != nil {
			return e
		}
	}
	if e = writeJSON(filepath.Join(p.Etc, "runtime.json"), rt); e != nil {
		return e
	}
	var dnsAPI *cloudflare.Client
	databaseCommitted := false
	if c.ManagedDNS {
		if e = advance("创建或恢复DNS"); e != nil {
			return e
		}
		dnsAPI, e = cloudflare.New(rt.TokenFile)
		if e != nil {
			return e
		}
		if host.DNSOperation != nil {
			if e = recoverDNS(ctx, p, &host, dnsAPI); e != nil {
				return e
			}
		}
		zone := *dnsZoneID
		if zone == "" {
			zone, e = dnsZone(ctx, dnsAPI, c.Domain)
			if e != nil {
				return e
			}
		}
		var previous *cloudflare.Record
		if setup, ok := ctx.Value(setupContextKey{}).(setupInput); ok {
			previous = setup.Previous
		} else if *adoptDNS {
			rows, err := dnsAPI.Records(ctx, zone, c.Domain)
			if err != nil {
				return err
			}
			if len(rows) > 1 {
				return cloudflare.ErrConflict
			}
			if len(rows) == 1 {
				r := rows[0]
				if r.Type != "A" && r.Type != "AAAA" {
					return cloudflare.ErrConflict
				}
				previous = &r
			}
		}
		defer func() {
			if resultErr != nil && !databaseCommitted && host.DNSOperation != nil {
				cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				resultErr = errors.Join(resultErr, abortDNSChange(cleanup, dnsAPI, &host, func() error { return saveHost(p, host) }))
			}
		}()
		if e = prepareDNSChange(ctx, dnsAPI, &host, model.Config{}, c, zone, previous, func() error { return saveHost(p, host) }); e != nil {
			return e
		}
	}
	var bundle cert.Bundle
	if e = advance("申请或导入证书"); e != nil {
		return e
	}
	if *certPath != "" || *keyPath != "" {
		bundle.Certificate, e = os.ReadFile(*certPath)
		if e != nil {
			return e
		}
		bundle.PrivateKey, e = os.ReadFile(*keyPath)
		if e != nil {
			return e
		}
	} else {
		if e = validateDomainAddress(ctx, c.EffectiveSubscriptionMode(), c.Domain, c.Address, net.DefaultResolver.LookupIPAddr); e != nil {
			return e
		}
		bundle, e = (cert.ACME{}).Obtain(ctx, cert.Options{Domain: c.Domain, Email: rt.Email, TokenFile: rt.TokenFile, DirectoryURL: rt.DirectoryURL, StateDir: filepath.Join(p.Data, "acme")})
		if e != nil {
			return e
		}
	}
	if e = advance("保存证书"); e != nil {
		return e
	}
	c.CertID, e = cert.Store(filepath.Join(p.Data, "certs"), bundle, c.Domain, time.Now())
	if e != nil {
		return e
	}
	if e = advance("生成与校验内核配置"); e != nil {
		return e
	}
	server, e := render.Server(c, p.render())
	if e != nil {
		return e
	}
	client := &core.Client{Binary: p.Core, WorkDir: p.Data, Socket: p.render().Socket}
	if e = client.Check(ctx, server); e != nil {
		return e
	}
	if e = advance("写入节点配置"); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(p.Data, "active.yaml"), server, 0600); e != nil {
		return e
	}
	if e = writeJSON(filepath.Join(p.Etc, "runtime.json"), rt); e != nil {
		return e
	}
	savedCert, loadErr := cert.Load(filepath.Join(p.Data, "certs"), c.CertID)
	if loadErr != nil {
		return loadErr
	}
	mode := "manual"
	if rt.TokenFile != "" {
		mode = "automatic"
	}
	if e = store.Initialize(filepath.Join(p.Data, "state.db"), store.Record{Config: c, Certificate: store.CertificateStatus{Expires: savedCert.NotAfter, Mode: mode}}); e != nil {
		return e
	}
	databaseCommitted = true
	if c.ManagedDNS {
		if e = advance("提交DNS状态"); e != nil {
			return e
		}
		if e = completeDNSChange(ctx, dnsAPI, &host, func() error { return saveHost(p, host) }); e != nil {
			return e
		}
	}
	if p.Root == "/" {
		if e = advance("配置服务权限"); e != nil {
			return e
		}
		host.InitPhase = "configured"
		rememberFirewallIntent(&host, c)
		if e = saveHost(p, host); e != nil {
			return e
		}
		if e = preparePermissions(p, host); e != nil {
			return e
		}
	}
	if !*noService && p.Root == "/" {
		if e = advance("安装并启动服务（含防火墙规则）"); e != nil {
			return e
		}
		if e = installUnits(ctx, p); e != nil {
			return e
		}
		if e = advance("服务健康检查"); e != nil {
			return e
		}
		if e = waitReady(ctx, p); e != nil {
			return e
		}
		host, e = loadHost(p)
		if e != nil {
			return e
		}
		host.InitPhase = "ready"
		if e = saveHost(p, host); e != nil {
			return e
		}
		if e = saveInstallProgress(p, "完成", true); e != nil {
			return e
		}
	}
	fmt.Fprintf(out, "初始化完成；订阅 https://%s:%d/s/%s/config.yaml\n", c.Domain, c.SubscriptionPort, c.Token)
	if *noService || p.Root != "/" {
		if e = advance("配置已准备，尚未启动服务"); e != nil {
			return e
		}
		fmt.Fprintln(out, "已准备配置，尚未启动服务")
	}
	return nil
}
