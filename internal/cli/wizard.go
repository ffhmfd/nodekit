package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/netip"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"nodekit/internal/terminal"
	"os"
	"strconv"
	"strings"
	"time"
)

type wizardDeps struct {
	Hostname func() (string, error)
	Discover func(context.Context) (string, string, error)
	Zones    func(context.Context, string) ([]cloudflare.Zone, error)
	Records  func(context.Context, string, string, string) ([]cloudflare.Record, error)
	Probe    func(context.Context, model.Reality) error
}
type setupInput struct {
	Config    model.Config       `json:"config"`
	Email     string             `json:"email"`
	Token     string             `json:"-"`
	TokenPath string             `json:"token_path"`
	ZoneID    string             `json:"zone_id"`
	Previous  *cloudflare.Record `json:"previous,omitempty"`
	Firewall  string             `json:"firewall"`
}

func discoverAddress(ctx context.Context) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return "", "", err
	}
	response, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return "", "", errors.New("public address discovery unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", "", errors.New("public address discovery unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(b) > 8192 {
		return "", "", errors.New("invalid discovery response")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	if _, err = netip.ParseAddr(values["ip"]); err != nil {
		return "", "", errors.New("discovery returned invalid IP")
	}
	country := values["loc"]
	if country == "XX" || model.CountryFlag(country) == "🌐" {
		country = ""
	}
	return values["ip"], country, nil
}

func defaultWizardDeps() wizardDeps {
	return wizardDeps{
		Hostname: os.Hostname, Discover: discoverAddress, Probe: probeReality,
		Zones: func(ctx context.Context, token string) ([]cloudflare.Zone, error) {
			return (&cloudflare.Client{Token: token}).Zones(ctx)
		},
		Records: func(ctx context.Context, token, zone, name string) ([]cloudflare.Record, error) {
			return (&cloudflare.Client{Token: token}).Records(ctx, zone, name)
		},
	}
}

func collectSetup(ctx context.Context, s *terminal.Session, deps wizardDeps) (setupInput, error) {
	var input setupInput
	if ctx.Err() != nil {
		return input, terminal.ErrCanceled
	}
	c, err := model.New()
	if err != nil {
		return input, err
	}
	ask := func(label, def string) (string, error) {
		if def != "" {
			label += " [" + def + "]"
		}
		v, e := s.ReadLine(ctx, label+": ", false)
		if e != nil {
			return "", e
		}
		if v == "" {
			return def, nil
		}
		return v, nil
	}
	mode, err := ask("订阅模式 direct/cloudflare", "cloudflare")
	if err != nil {
		return input, err
	}
	address, country, lookupErr := deps.Discover(ctx)
	if ctx.Err() != nil {
		return input, terminal.ErrCanceled
	}
	if lookupErr != nil {
		s.Printf("自动检测不可用，请手工填写公网IP。\n")
	}
	c.Address, err = ask("VPS公网IP", address)
	if err != nil {
		return input, err
	}
	parsed, err := netip.ParseAddr(c.Address)
	if err != nil {
		return input, errors.New("invalid public IP")
	}
	c.Address = parsed.Unmap().String()
	c.IPv6 = parsed.Unmap().Is6()
	if err = (model.Config{SubscriptionMode: "cloudflare", SubscriptionPort: 8443, Address: c.Address, IPv6: c.IPv6}).ValidateSubscription(); err != nil {
		return input, err
	}
	if err = c.SetSubscriptionMode(mode); err != nil {
		return input, err
	}
	input.Token, err = s.ReadLine(ctx, "Cloudflare Token（直接粘贴，不回显）: ", true)
	if err != nil {
		return input, err
	}
	if len(input.Token) < 10 || strings.ContainsAny(input.Token, "\r\n") {
		return input, errors.New("invalid Token")
	}
	zones, err := deps.Zones(ctx, input.Token)
	if err != nil {
		return input, err
	}
	if len(zones) == 0 {
		return input, errors.New("Token cannot read any zone; requires Zone Read and DNS Edit")
	}
	for i, zone := range zones {
		s.Printf("%d %s (%s)\n", i+1, zone.Name, zone.Status)
	}
	selection, err := ask("选择区域编号", "1")
	if err != nil {
		return input, err
	}
	index, err := strconv.Atoi(selection)
	if err != nil || index < 1 || index > len(zones) {
		return input, errors.New("invalid zone selection")
	}
	zone := zones[index-1]
	if zone.Status != "active" {
		return input, errors.New("selected zone is not active")
	}
	input.ZoneID = zone.ID
	name, err := ask("专用子域名前缀或完整域名", "")
	if err != nil {
		return input, err
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone.Name = strings.ToLower(zone.Name)
	if strings.HasSuffix(name, "."+zone.Name) {
		c.Domain = name
	} else if !strings.Contains(name, ".") && name != "" {
		c.Domain = name + "." + zone.Name
	} else {
		return input, errors.New("use a dedicated subdomain within the selected zone")
	}
	if !model.ValidDomain(c.Domain) || c.Domain == zone.Name {
		return input, errors.New("invalid dedicated subdomain")
	}
	records, err := deps.Records(ctx, input.Token, zone.ID, c.Domain)
	if err != nil {
		return input, err
	}
	if len(records) > 1 {
		return input, errors.New("multiple existing records; use a dedicated name or resolve conflicting records first")
	}
	if len(records) == 1 {
		r := records[0]
		if r.Type != "A" && r.Type != "AAAA" {
			return input, errors.New("existing CNAME or other DNS type; select another dedicated name")
		}
		s.Printf("现有记录 %s %s → %s，代理=%t。接管后彻底卸载会删除此记录。\n", r.Type, r.Name, r.Content, r.Proxied)
		answer, e := ask("输入 adopt 接管/更新，其他输入返回", "")
		if e != nil {
			return input, e
		}
		if answer != "adopt" {
			return input, terminal.ErrCanceled
		}
		input.Previous = &r
	}
	input.Email, err = ask("ACME邮箱", "")
	if err != nil {
		return input, err
	}
	email, err := mail.ParseAddress(input.Email)
	if err != nil || email.Address != input.Email {
		return input, errors.New("invalid ACME email")
	}
	host, _ := deps.Hostname()
	if strings.TrimSpace(host) == "" {
		host = "NodeKit"
	}
	host, err = ask("节点显示主机名", host)
	if err != nil {
		return input, err
	}
	country, err = ask("国家代码（如JP；none使用🌐）", country)
	if err != nil {
		return input, err
	}
	if country == "none" {
		country = ""
	}
	if err = c.SetDisplayDefaults(host, country); err != nil {
		return input, err
	}
	sni, err := ask("REALITY SNI（同步目标443）", "addons.mozilla.org")
	if err != nil {
		return input, err
	}
	if err = c.SetRealityServerName(sni); err != nil {
		return input, err
	}
	protocols, err := ask("启用协议 all 或逗号分隔 vless,ss,tuic,hy2,anytls", "all")
	if err != nil {
		return input, err
	}
	if protocols != "all" {
		selected := map[string]bool{}
		for _, typ := range strings.Split(protocols, ",") {
			typ = strings.TrimSpace(typ)
			if typ == "hy2" {
				typ = "hysteria2"
			}
			if typ == "ss2022" {
				typ = "ss"
			}
			if model.ProtocolLabel(typ) == typ {
				return input, errors.New("unknown protocol selection")
			}
			selected[typ] = true
		}
		for i := range c.Protocols {
			c.Protocols[i].Enabled = selected[c.Protocols[i].Type]
		}
	}
	ports, err := ask("自定义端口（如vless=24441,subscription=8443；空为默认）", "")
	if err != nil {
		return input, err
	}
	if ports != "" {
		for _, entry := range strings.Split(ports, ",") {
			typ, value, ok := strings.Cut(strings.TrimSpace(entry), "=")
			if !ok {
				return input, errors.New("invalid port assignments")
			}
			port, e := strconv.Atoi(value)
			if e != nil {
				return input, e
			}
			if typ == "subscription" {
				c.SubscriptionPort = port
				continue
			}
			if typ == "hy2" {
				typ = "hysteria2"
			}
			found := false
			for i := range c.Protocols {
				if c.Protocols[i].Type == typ {
					c.Protocols[i].Port = port
					found = true
				}
			}
			if !found {
				return input, errors.New("unknown port assignment")
			}
		}
	}
	individual, err := ask("逐协议自定义名称？输入yes，回车使用自动名称", "")
	if err != nil {
		return input, err
	}
	if individual == "yes" {
		for i := range c.Protocols {
			if !c.Protocols[i].Enabled {
				continue
			}
			name, e := ask(c.Protocols[i].Type+"名称（空为自动："+c.NodeName(c.Protocols[i])+"）", "")
			if e != nil {
				return input, e
			}
			if name != "auto" {
				c.Protocols[i].Name = name
			}
		}
	}
	quota, err := ask("流量额度（如500GB；空为不展示）", "")
	if err != nil {
		return input, err
	}
	if quota != "" {
		c.Quota, err = model.ParseBytes(quota)
		if err != nil {
			return input, err
		}
	}
	expiry, err := ask("到期北京时间 YYYY-MM-DD HH:mm（空为不设置）", "")
	if err != nil {
		return input, err
	}
	if expiry != "" {
		value, e := model.ParseExpiry(expiry)
		if e != nil {
			return input, e
		}
		c.Expiry = &value
	}
	reset, err := ask("每月清零 日@小时（北京时间）", "1@0")
	if err != nil {
		return input, err
	}
	day, hour, ok := strings.Cut(reset, "@")
	if !ok {
		return input, errors.New("invalid reset schedule")
	}
	c.ResetDay, err = strconv.Atoi(day)
	if err != nil {
		return input, err
	}
	c.ResetHour, err = strconv.Atoi(hour)
	if err != nil {
		return input, err
	}
	input.Firewall, err = ask("防火墙 auto/manual", "auto")
	if err != nil {
		return input, err
	}
	if input.Firewall != "auto" && input.Firewall != "manual" {
		return input, errors.New("invalid firewall mode")
	}
	c.ManagedDNS = true
	if err = c.Validate(); err != nil {
		return input, err
	}
	if err = deps.Probe(ctx, c.Reality); err != nil {
		return input, err
	}
	s.Printf("准备配置 %s → %s，%s，订阅端口%d。\n", c.Domain, c.Address, c.EffectiveSubscriptionMode(), c.SubscriptionPort)
	for _, p := range c.Protocols {
		if p.Enabled {
			s.Printf("  %s 端口%d\n", c.NodeName(p), p.Port)
		}
	}
	s.Printf("Token将自动保存到/root/nodekit-cloudflare.token及续期副本/etc/nodekit/cloudflare.token；普通卸载保留，彻底卸载删除这两个受限文件及本节点DNS，不撤销API Token。\n")
	if mode == "cloudflare" {
		s.Printf("请确认Cloudflare回源为Full(strict)，云安全组放行上述端口。\n")
	}
	answer, err := ask("输入 yes 提交，其他输入返回", "")
	if err != nil {
		return input, err
	}
	if answer != "yes" {
		return input, terminal.ErrCanceled
	}
	input.Config = c
	return input, nil
}
