package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"nodekit/internal/terminal"
	"os"
	"os/signal"
	"strings"
)

func interrupted(ctx context.Context, signals <-chan os.Signal, fn func(context.Context) error) error {
	op, cancel := context.WithCancel(ctx)
	defer cancel()
	done, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-signals:
			cancel()
		case <-done:
		case <-ctx.Done():
			cancel()
		}
	}()
	err := fn(op)
	close(done)
	<-joined
	return err
}

func menu(ctx context.Context, p paths, in io.Reader, out, errOut io.Writer) int {
	return menuInitial(ctx, p, in, out, errOut, "")
}

func menuInitial(ctx context.Context, p paths, in io.Reader, out, errOut io.Writer, initial string) int {
	s := terminal.New(in, out)
	ctx = terminal.WithSession(ctx, s)
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	for ctx.Err() == nil {
		fmt.Fprintln(out, "\nNodeKit\n1 初始化安装\n2 状态\n3 订阅链接\n4 手动清零\n5 修改额度\n6 修改到期时间\n7 每月清零安排\n8 协议管理\n9 更新证书\n10 查看日志\n11 升级程序\n12 回滚版本\n13 保留数据卸载\n14 恢复未完成升级\n15 恢复保留的安装\n16 修改订阅模式\n17 修改节点公网 IP\n18 修改订阅端口\n19 修改名称/国旗\n20 修改 REALITY\n21 彻底卸载\n22 DNS管理/恢复\n23 继续未完成安装向导\n24 IPv6节点管理\n0 退出\n主菜单 Ctrl+C 退出；配置输入 Ctrl+C 返回")
		var choice string
		var err error
		if initial != "" {
			choice = initial
			initial = ""
		} else {
			err = interrupted(ctx, interrupts, func(op context.Context) error {
				var e error
				choice, e = s.ReadLine(op, "请输入编号: ", false)
				if e == nil && op.Err() != nil {
					return terminal.ErrCanceled
				}
				return e
			})
		}
		if err != nil || choice == "0" {
			return 0
		}
		err = interrupted(ctx, interrupts, func(op context.Context) error { return menuAction(op, p, s, choice, in, out) })
		if errors.Is(err, io.EOF) {
			return 0
		}
		if errors.Is(err, errConfigApplied) {
			fmt.Fprintln(out, err)
			continue
		}
		if errors.Is(err, terminal.ErrCanceled) || errors.Is(err, context.Canceled) {
			fmt.Fprintln(out, "已取消当前操作，返回主菜单")
			continue
		}
		if err != nil {
			fmt.Fprintln(errOut, err)
		}
	}
	return 0
}

func menuAction(ctx context.Context, p paths, s *terminal.Session, choice string, in io.Reader, out io.Writer) error {
	read := func(label string) (string, error) { return s.ReadLine(ctx, label, false) }
	var args []string
	switch choice {
	case "1":
		args = []string{"setup"}
	case "2":
		args = []string{"status"}
	case "3":
		args = []string{"subscription"}
	case "4":
		args = []string{"usage", "reset"}
	case "5", "6", "7":
		key := map[string]string{"5": "quota", "6": "expiry", "7": "reset"}[choice]
		v, e := read("输入值（额度如500GB；到期如2026-12-31 18:00；清零如15@8）: ")
		if e != nil {
			return e
		}
		args = []string{"config", "set", key, v}
	case "8":
		v, e := read("输入 enable|disable|port|rotate|name 协议 [值]，0返回: ")
		if e != nil {
			return e
		}
		if v == "0" {
			return nil
		}
		args = append([]string{"protocol"}, strings.Fields(v)...)
	case "9":
		args = []string{"cert", "renew"}
	case "10":
		args = []string{"logs"}
	case "11":
		file, e := read("发布包路径: ")
		if e != nil {
			return e
		}
		sha, e := read("可信的 SHA256: ")
		if e != nil {
			return e
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
		v, e := read("输入 " + key + "（模式direct/cloudflare；橙云端口2053/2083/2087/2096/8443）: ")
		if e != nil {
			return e
		}
		args = []string{"config", "set", key, v}
	case "19":
		v, e := read("1显示前缀 2国家代码 3名称风格 4单个协议名称 0返回: ")
		if e != nil {
			return e
		}
		if v == "0" {
			return nil
		}
		if v == "4" {
			typ, e := read("协议 vless/ss/tuic/hy2/anytls: ")
			if e != nil {
				return e
			}
			name, e := read("完整显示名称（auto恢复自动）: ")
			if e != nil {
				return e
			}
			args = []string{"protocol", "name", typ, name}
		} else {
			key := map[string]string{"1": "name", "2": "country", "3": "name-style"}[v]
			if key == "" {
				return errors.New("无效选项")
			}
			value, e := read("输入 " + key + "（国家如JP；风格flag-host或legacy）: ")
			if e != nil {
				return e
			}
			args = []string{"config", "set", key, value}
		}
	case "20":
		v, e := read("1修改SNI（同步目标443） 2高级握手目标 0返回: ")
		if e != nil {
			return e
		}
		if v == "0" {
			return nil
		}
		key := map[string]string{"1": "reality-sni", "2": "reality-target"}[v]
		if key == "" {
			return errors.New("无效选项")
		}
		value, e := read("输入 " + key + "（默认addons.mozilla.org / addons.mozilla.org:443）: ")
		if e != nil {
			return e
		}
		args = []string{"config", "set", key, value}
	case "21":
		if err := purgeSummary(ctx, p, out); err != nil {
			return err
		}
		v, e := read("彻底卸载将删除上述DNS、项目数据及/root/nodekit-cloudflare.token，不撤销API Token。输入 purge 确认: ")
		if e != nil {
			return e
		}
		if v != "purge" {
			return nil
		}
		args = []string{"uninstall", "--purge"}
	case "22":
		choice, err := read("1托管DNS状态 2接管当前节点DNS 3恢复DNS操作 0返回: ")
		if err != nil {
			return err
		}
		if choice == "0" {
			return nil
		}
		action := map[string]string{"1": "status", "2": "adopt", "3": "recover"}[choice]
		if action == "" {
			return errors.New("无效选项")
		}
		if action == "adopt" {
			answer, err := read("接管当前域名对应记录后，彻底卸载会删除它。输入adopt确认: ")
			if err != nil {
				return err
			}
			if answer != "adopt" {
				return nil
			}
		}
		args = []string{"dns", action}
	case "23":
		args = []string{"setup", "--resume"}
	case "24":
		return ipv6Menu(ctx, p, s, out, defaultIPv6Deps())
	default:
		fmt.Fprintln(out, "无效选项")
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return execute(ctx, p, args, in, out)
}
