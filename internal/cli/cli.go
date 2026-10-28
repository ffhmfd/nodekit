package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"nodekit/internal/cert"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("nodekit", flag.ContinueOnError)
	flags.SetOutput(errOut)
	root := flags.String("root", "/", "isolated filesystem root")
	coreBin := flags.String("core-bin", "", "core binary override")
	if e := flags.Parse(args); e != nil {
		return 2
	}
	args = flags.Args()
	p := makePaths(*root, *coreBin)
	if len(args) == 0 {
		return menu(ctx, p, in, out, errOut)
	}
	if args[0] == "help" || args[0] == "--help" {
		fmt.Fprintln(out, "NodeKit — install | init | resume | recover | serve | status | config [export|apply|set] | protocol [enable|disable|port|rotate] | subscription [rotate] | usage reset | cert renew | logs | firewall [apply|remove] | uninstall | upgrade | rollback")
		return 0
	}
	if args[0] == "capabilities" {
		if e := json.NewEncoder(out).Encode(capabilities{SubscriptionModes: []string{"direct", "cloudflare"}}); e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		return 0
	}
	known := map[string]bool{"install": true, "resume": true, "recover": true, "inspect": true, "snapshot": true, "prepare": true, "init": true, "serve": true, "status": true, "config": true, "protocol": true, "subscription": true, "usage": true, "cert": true, "logs": true, "firewall": true, "uninstall": true, "upgrade": true, "rollback": true}
	if !known[args[0]] {
		fmt.Fprintln(errOut, "未知命令:", args[0])
		return 2
	}
	e := execute(ctx, p, args, in, out)
	if e != nil {
		fmt.Fprintln(errOut, "操作失败:", e)
		return 1
	}
	return 0
}
func callHTTP(ctx context.Context, hc *http.Client, method, url string, body, out any) error {
	var data io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		data = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, url, data)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	r, e := hc.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		return fmt.Errorf("管理接口 %d: %s", r.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(r.Body).Decode(out)
	}
	return nil
}
func execute(ctx context.Context, p paths, args []string, in io.Reader, out io.Writer) error {
	switch args[0] {
	case "inspect", "snapshot", "prepare":
		return serviceDataCommand(ctx, p, args[0], out)
	case "recover":
		return recoverCommand(ctx, p, len(args) > 1 && args[1] == "--boot")
	case "install":
		return installPackage(ctx, p, args[1:], out)
	case "resume":
		return resume(ctx, p)
	case "init":
		return initialize(ctx, p, args[1:], in, out)
	case "serve":
		return serve(ctx, p)
	case "status":
		var r store.Record
		if e := p.admin(ctx, "GET", "/status", nil, &r); e != nil {
			return e
		}
		loc, _ := time.LoadLocation("Asia/Shanghai")
		fmt.Fprintf(out, "订阅模式: %s\n节点连接地址: %s\n订阅端口: %d\n", r.Config.EffectiveSubscriptionMode(), r.Config.NodeAddress(), r.Config.SubscriptionPort)
		fmt.Fprintf(out, "%s\n已用上传: %d B\n已用下载: %d B\n额度: %d B（仅展示）\n每月 %d 日 %02d:00 北京时间清零\n下次清零: %s\n最近采集: %s\n", r.Config.Name, r.Meter.Upload, r.Meter.Download, r.Config.Quota, r.Config.ResetDay, r.Config.ResetHour, r.Meter.Next.In(loc).Format("2006-01-02 15:04"), r.Meter.LastSample.In(loc).Format("2006-01-02 15:04:05"))
		if r.Config.Expiry != nil {
			fmt.Fprintln(out, "到期:", r.Config.Expiry.In(loc).Format("2006-01-02 15:04"))
		}
		if r.LastError != "" {
			fmt.Fprintln(out, r.LastError)
		}
		if r.SamplingError != "" {
			fmt.Fprintln(out, r.SamplingError)
		}
		if r.OperationPhase != "" {
			fmt.Fprintln(out, "待恢复操作:", r.OperationPhase)
		}
		if !r.Certificate.Expires.IsZero() {
			fmt.Fprintln(out, "TLS 证书到期:", r.Certificate.Expires.In(loc).Format("2006-01-02 15:04"), "模式:", r.Certificate.Mode)
		}
		if r.Certificate.Error != "" {
			fmt.Fprintln(out, "证书状态:", r.Certificate.Error)
		}
		if !r.Certificate.NextAttempt.IsZero() {
			fmt.Fprintln(out, "下次证书检查/尝试:", r.Certificate.NextAttempt.In(loc).Format("2006-01-02 15:04"))
		}
		if r.Meter.Gap != "" {
			fmt.Fprintln(out, "统计提示:", r.Meter.Gap)
		}
		return nil
	case "usage":
		if len(args) != 2 || args[1] != "reset" {
			return errors.New("usage reset")
		}
		return p.admin(ctx, "POST", "/usage/reset", nil, nil)
	case "config", "protocol", "subscription", "cert":
		return edit(ctx, p, args, out)
	case "logs":
		cmd := exec.CommandContext(ctx, "journalctl", "-u", "nodekit-core", "-u", "nodekit-manager", "-n", "100", "--no-pager")
		cmd.Stdout = out
		cmd.Stderr = out
		return cmd.Run()
	case "firewall":
		if os.Geteuid() != 0 {
			return errors.New("firewall 操作需要 root")
		}
		if len(args) != 2 {
			return errors.New("firewall apply|remove")
		}
		rt, e := p.runtime()
		if e != nil {
			return e
		}
		if rt.Firewall == "manual" {
			return nil
		}
		m, e := loadHost(p)
		if e != nil {
			return e
		}
		if e = verifyAccount(p, m); e != nil {
			return e
		}
		rules := m.Firewall
		if m.PendingFirewall != nil {
			rules = bindingsUnion(rules, bindingsUnion(m.PendingFirewall.Old, m.PendingFirewall.New))
		}
		f := platform.Firewall{}
		if args[1] == "apply" {
			lock, lockErr := operationLock(p)
			if lockErr == nil {
				defer lock.Close()
				if m.PendingFirewall != nil {
					c, e := serviceConfig(ctx, p)
					if e != nil {
						return e
					}
					m, e = reconcileFirewall(ctx, p, m, c)
					if e != nil {
						return e
					}
					rules = m.Firewall
				}
			} else if !errors.Is(lockErr, platform.ErrLocked) {
				return lockErr
			}
			return f.Apply(ctx, rules)
		}
		if args[1] == "remove" {
			return f.Remove(ctx, rules)
		}
		return errors.New("firewall apply|remove")
	case "uninstall":
		return uninstall(ctx, p, len(args) > 1 && args[1] == "--purge", out)
	case "upgrade", "rollback":
		return releaseCommand(ctx, p, args, out)
	}
	return errors.New("unsupported command")
}
func edit(ctx context.Context, p paths, args []string, out io.Writer) error {
	if p.Root == "/" && os.Geteuid() == 0 {
		lock, e := operationLock(p)
		if e != nil {
			return e
		}
		defer lock.Close()
	}
	var c model.Config
	if e := p.admin(ctx, "GET", "/config", nil, &c); e != nil {
		return e
	}
	old := c.Clone()
	switch args[0] {
	case "subscription":
		if len(args) == 1 {
			fmt.Fprintf(out, "完整配置: https://%s:%d/s/%s/config.yaml\n纯节点: https://%s:%d/s/%s/proxies.yaml\n", c.Domain, c.SubscriptionPort, c.Token, c.Domain, c.SubscriptionPort, c.Token)
			return nil
		}
		if args[1] != "rotate" {
			return errors.New("subscription [rotate]")
		}
		var e error
		c.Token, e = model.RandomToken()
		if e != nil {
			return e
		}
	case "config":
		if len(args) < 2 || args[1] == "export" {
			return json.NewEncoder(out).Encode(c)
		}
		if args[1] == "apply" {
			if len(args) != 3 {
				return errors.New("config apply <JSON文件>")
			}
			b, e := os.ReadFile(args[2])
			if e != nil {
				return e
			}
			// Missing mode in legacy JSON always means direct, even when the
			// active configuration currently uses cloudflare.
			c.SubscriptionMode = ""
			if e = json.Unmarshal(b, &c); e != nil {
				return e
			}
		} else if args[1] == "set" {
			if len(args) != 4 {
				return errors.New("config set quota|expiry|reset|name|domain|address|subscription-mode|subscription-port <值>")
			}
			switch args[2] {
			case "address":
				c.Address = args[3]
			case "subscription-mode":
				if e := c.SetSubscriptionMode(args[3]); e != nil {
					return e
				}
				fmt.Fprintf(out, "切换订阅模式为 %s，候选 HTTPS 端口: %d\n", c.EffectiveSubscriptionMode(), c.SubscriptionPort)
			case "quota":
				n, e := model.ParseBytes(args[3])
				if e != nil {
					return e
				}
				c.Quota = n
			case "expiry":
				if args[3] == "none" {
					c.Expiry = nil
				} else {
					v, e := model.ParseExpiry(args[3])
					if e != nil {
						return e
					}
					c.Expiry = &v
				}
			case "reset":
				parts := strings.Split(args[3], "@")
				if len(parts) != 2 {
					return errors.New("reset 格式 日@小时，例如 15@8")
				}
				d, e := strconv.Atoi(parts[0])
				if e != nil {
					return e
				}
				h, e := strconv.Atoi(parts[1])
				if e != nil {
					return e
				}
				c.ResetDay = d
				c.ResetHour = h
			case "name":
				c.Name = args[3]
			case "domain":
				return p.admin(ctx, "POST", "/cert/renew", map[string]string{"domain": args[3]}, nil)
			case "subscription-port":
				n, e := strconv.Atoi(args[3])
				if e != nil {
					return e
				}
				c.SubscriptionPort = n
			default:
				return errors.New("未知设置项")
			}
		} else {
			return errors.New("config export|apply|set")
		}
	case "protocol":
		if len(args) < 3 {
			return errors.New("protocol enable|disable|port|rotate <协议> [端口]")
		}
		typ := args[2]
		if typ == "hy2" {
			typ = "hysteria2"
		}
		if typ == "ss2022" {
			typ = "ss"
		}
		found := false
		for i := range c.Protocols {
			if c.Protocols[i].Type != typ {
				continue
			}
			found = true
			switch args[1] {
			case "enable":
				c.Protocols[i].Enabled = true
			case "disable":
				c.Protocols[i].Enabled = false
			case "port":
				if len(args) != 4 {
					return errors.New("缺少端口")
				}
				n, e := strconv.Atoi(args[3])
				if e != nil {
					return e
				}
				c.Protocols[i].Port = n
			case "rotate":
				fresh, e := model.New()
				if e != nil {
					return e
				}
				for _, v := range fresh.Protocols {
					if v.Type == typ {
						c.Protocols[i].UUID = v.UUID
						c.Protocols[i].Password = v.Password
					}
				}
			default:
				return errors.New("未知协议操作")
			}
		}
		if !found {
			return errors.New("未知协议")
		}
	case "cert":
		if len(args) < 2 || args[1] != "renew" {
			return errors.New("cert renew [--domain <domain>]")
		}
		domain := ""
		if len(args) == 4 && args[2] == "--domain" {
			domain = args[3]
		} else if len(args) != 2 {
			return errors.New("cert renew [--domain <domain>]")
		}
		return p.admin(ctx, "POST", "/cert/renew", map[string]string{"domain": domain}, nil)
	}
	if e := c.Validate(); e != nil {
		return e
	}
	if c.CertID != "" {
		b, e := cert.Load(filepath.Join(p.Data, "certs"), c.CertID)
		if e != nil {
			return e
		}
		if e = cert.Validate(b, c.Domain, time.Now()); e != nil {
			return fmt.Errorf("域名证书不匹配，先申请对应证书再导入配置: %w", e)
		}
	}
	if e := platform.CheckPorts(c, platform.Bindings(old)); e != nil {
		return e
	}
	rt, e := p.runtime()
	if e != nil {
		return e
	}
	commitFirewall, abortFirewall := func() error { return nil }, func() error { return nil }
	if rt.Firewall != "manual" {
		if os.Geteuid() != 0 || p.Root != "/" {
			return errors.New("自动防火墙操作需真实系统 root")
		}
		commitFirewall, abortFirewall, e = beginFirewallChange(ctx, p, old, c)
		if e != nil {
			return e
		}
	}
	if e = p.admin(ctx, "PUT", "/config", c, nil); e != nil {
		return errors.Join(e, abortFirewall())
	}
	if e = commitFirewall(); e != nil {
		return e
	}
	fmt.Fprintln(out, "配置已更新")
	return nil
}
func difference(a, b []platform.Binding) []platform.Binding {
	set := map[platform.Binding]bool{}
	for _, v := range b {
		set[v] = true
	}
	var out []platform.Binding
	for _, v := range a {
		if !set[v] {
			out = append(out, v)
		}
	}
	return out
}
func menu(ctx context.Context, p paths, in io.Reader, out, errOut io.Writer) int {
	reader := bufio.NewReader(in)
	readLine := func() (string, bool) {
		line, e := reader.ReadString('\n')
		if e != nil && len(line) == 0 {
			return "", false
		}
		return strings.TrimSpace(line), true
	}
	for {
		fmt.Fprintln(out, "\nNodeKit\n1 初始化安装\n2 状态\n3 订阅链接\n4 手动清零\n5 修改额度\n6 修改到期时间\n7 每月清零安排\n8 协议管理\n9 更新证书\n10 查看日志\n11 升级程序\n12 回滚版本\n13 保留数据卸载\n14 恢复未完成升级\n15 恢复保留的安装\n16 修改订阅模式\n17 修改节点公网 IP\n18 修改订阅端口\n0 退出\n请输入编号:")
		choice, ok := readLine()
		if !ok {
			return 0
		}
		var args []string
		switch choice {
		case "0":
			return 0
		case "1":
			args = []string{"init"}
		case "2":
			args = []string{"status"}
		case "3":
			args = []string{"subscription"}
		case "4":
			args = []string{"usage", "reset"}
		case "5", "6", "7":
			key := map[string]string{"5": "quota", "6": "expiry", "7": "reset"}[choice]
			fmt.Fprintln(out, "输入值（额度如 500GB；到期如 2026-12-31 18:00；清零如 15@8）:")
			value, ok := readLine()
			if !ok {
				return 0
			}
			args = []string{"config", "set", key, value}
		case "8":
			fmt.Fprintln(out, "输入 enable|disable|port|rotate 协议 [端口]:")
			value, ok := readLine()
			if !ok {
				return 0
			}
			args = append([]string{"protocol"}, strings.Fields(value)...)
		case "9":
			args = []string{"cert", "renew"}
		case "10":
			args = []string{"logs"}
		case "11":
			fmt.Fprintln(out, "发布包路径:")
			file, ok := readLine()
			if !ok {
				return 0
			}
			fmt.Fprintln(out, "可信的 SHA256:")
			sha, ok := readLine()
			if !ok {
				return 0
			}
			args = []string{"upgrade", "--file", file, "--sha256", sha}
		case "12":
			args = []string{"rollback"}
		case "13":
			args = []string{"uninstall"}
		case "14":
			args = []string{"recover"}
		case "15":
			args = []string{"resume"}
		case "16", "17", "18":
			key := map[string]string{"16": "subscription-mode", "17": "address", "18": "subscription-port"}[choice]
			fmt.Fprintln(out, "输入", key, "（模式 direct/cloudflare；橙云端口 2053/2083/2087/2096/8443）:")
			value, ok := readLine()
			if !ok {
				return 0
			}
			args = []string{"config", "set", key, value}
		default:
			fmt.Fprintln(out, "无效选项")
			continue
		}
		if e := execute(ctx, p, args, reader, out); e != nil {
			fmt.Fprintln(errOut, e)
		}
	}
}

func installUnits(ctx context.Context, p paths) error {
	if os.Geteuid() != 0 || p.Root != "/" {
		return errors.New("systemd 安装需真实系统 root")
	}
	m, e := loadHost(p)
	if e != nil {
		return e
	}
	if e = verifyAccount(p, m); e != nil {
		return e
	}
	if e = checkOwnedFiles(m); e != nil {
		return e
	}
	files, e := unitFiles(p)
	if e != nil {
		return e
	}
	for path, b := range files {
		m.Files[path] = hashBytes(b)
	}
	if e = saveHost(p, m); e != nil {
		return e
	}
	for path, b := range files {
		if e = platform.WritePrivate(path, b); e != nil {
			return e
		}
		if e = os.Chmod(path, 0644); e != nil {
			return e
		}
	}
	for _, args := range [][]string{{"systemd-tmpfiles", "--create", "/etc/tmpfiles.d/nodekit.conf"}, {"systemctl", "daemon-reload"}, {"systemctl", "enable", "--now", "nodekit-core.service", "nodekit-manager.service"}} {
		if _, e := platform.Exec(ctx, args...); e != nil {
			return e
		}
	}
	return nil
}
