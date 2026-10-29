package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/terminal"
	"sort"
	"strconv"
	"strings"
)

type localAddress struct {
	Interface string
	Address   netip.Addr
	Up        bool
}

type ipv6Deps struct {
	Addresses  func() ([]localAddress, error)
	CheckPorts func(model.Config, []platform.Binding) error
}

func defaultIPv6Deps() ipv6Deps {
	return ipv6Deps{Addresses: localInterfaceAddresses, CheckPorts: platform.CheckPorts}
}

func localInterfaceAddresses() ([]localAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []localAddress
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			result = append(result, localAddress{Interface: iface.Name, Address: prefix.Addr(), Up: true})
		}
	}
	return result, nil
}

func publicIPv6Candidate(ip netip.Addr) bool {
	if !ip.Is6() || ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	// Match the special-use IPv6 exclusions in model subscription validation.
	for _, value := range []string{"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		if netip.MustParsePrefix(value).Contains(ip) {
			return false
		}
	}
	return true
}

func ipv6Candidates(addresses []localAddress) []localAddress {
	var candidates []localAddress
	seen := map[netip.Addr]bool{}
	for _, candidate := range addresses {
		if candidate.Up && publicIPv6Candidate(candidate.Address) && !seen[candidate.Address] {
			seen[candidate.Address] = true
			candidates = append(candidates, candidate)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Address.Less(candidates[j].Address) })
	return candidates
}

func ipv4ListenAddresses(addresses []localAddress, primary string) ([]string, error) {
	var ips []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, candidate := range addresses {
		ip := candidate.Address
		if candidate.Up && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("未检测到可用的本机IPv4监听地址；不能替换现有入口")
	}
	sort.Slice(ips, func(i, j int) bool {
		primaryI, primaryJ := ips[i].String() == primary, ips[j].String() == primary
		if primaryI != primaryJ {
			return primaryI
		}
		if ips[i].IsLoopback() != ips[j].IsLoopback() {
			return !ips[i].IsLoopback()
		}
		return ips[i].Less(ips[j])
	})
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result, nil
}

func parseIPv6Protocols(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("请显式选择至少一个IPv6协议，不会自动复制IPv4协议")
	}
	var result []string
	seen := map[string]bool{}
	for _, typ := range strings.Split(value, ",") {
		typ = strings.ToLower(strings.TrimSpace(typ))
		if typ == "hy2" {
			typ = "hysteria2"
		}
		if typ == "ss2022" {
			typ = "ss"
		}
		if model.ProtocolLabel(typ) == typ || seen[typ] {
			return nil, errors.New("IPv6协议未知或重复")
		}
		seen[typ] = true
		result = append(result, typ)
	}
	return result, nil
}

func validateLocalIPv6Nodes(c model.Config, deps ipv6Deps) error {
	if c.IPv6Nodes == nil {
		return nil
	}
	addresses, err := deps.Addresses()
	if err != nil {
		return err
	}
	assigned := map[string]bool{}
	for _, address := range addresses {
		if address.Up {
			assigned[address.Address.String()] = true
		}
	}
	for _, address := range c.IPv6Nodes.IPv4ListenAddresses {
		if !assigned[address] {
			return fmt.Errorf("IPv4监听地址%s未在有效网卡上分配，请重新配置IPv6节点", address)
		}
	}
	if c.HasIPv6Nodes() && !assigned[c.IPv6Nodes.Address] {
		return errors.New("所选公网IPv6未在本机有效网卡上分配；不会修改网卡或路由")
	}
	return nil
}

func configureIPv6Nodes(c *model.Config, address, selection string, deps ipv6Deps) error {
	primary, primaryErr := netip.ParseAddr(c.Address)
	if c.IPv6 || primaryErr != nil || !primary.Is4() {
		return errors.New("此功能用于已完成的IPv4安装；旧IPv6/双栈安装保持原行为，不能直接叠加")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil || !publicIPv6Candidate(ip) {
		return errors.New("请输入本机已分配的公网原生IPv6地址，不带方括号或zone")
	}
	protocols, err := parseIPv6Protocols(selection)
	if err != nil {
		return err
	}
	addresses, err := deps.Addresses()
	if err != nil {
		return err
	}
	binds, err := ipv4ListenAddresses(addresses, c.Address)
	if err != nil {
		return err
	}
	next := c.Clone()
	next.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: ip.String(), Protocols: protocols, IPv4ListenAddresses: binds}
	if err := next.Validate(); err != nil {
		return err
	}
	if err := validateLocalIPv6Nodes(next, deps); err != nil {
		return err
	}
	*c = next
	return nil
}

func printIPv6Status(out io.Writer, c model.Config) {
	if c.IPv6Nodes == nil {
		fmt.Fprintln(out, "IPv6节点：未配置；请先完成IPv4初始化后选择协议。")
		return
	}
	state := "已关闭（保留设置）"
	if c.HasIPv6Nodes() {
		state = "已启用"
	}
	fmt.Fprintf(out, "IPv6节点：%s，地址：%s\n", state, c.IPv6Nodes.Address)
	for _, p := range c.Protocols {
		for _, typ := range c.IPv6Nodes.Protocols {
			if p.Type == typ {
				fmt.Fprintf(out, "  %s 端口%d\n", model.ProtocolLabel(typ), p.Port)
			}
		}
	}
}

func changeIPv6Config(c *model.Config, args []string, out io.Writer, deps ipv6Deps) (bool, error) {
	if len(args) == 0 || (len(args) == 1 && args[0] == "status") {
		printIPv6Status(out, *c)
		return false, nil
	}
	switch args[0] {
	case "configure":
		fs := flag.NewFlagSet("ipv6 configure", flag.ContinueOnError)
		fs.SetOutput(out)
		address := fs.String("address", "", "assigned public IPv6")
		protocols := fs.String("protocols", "", "explicit protocol selection")
		if err := fs.Parse(args[1:]); err != nil {
			return false, err
		}
		if fs.NArg() != 0 {
			return false, errors.New("ipv6 configure --address <IPv6> --protocols <协议列表>")
		}
		if err := configureIPv6Nodes(c, *address, *protocols, deps); err != nil {
			return false, err
		}
	case "enable":
		if len(args) != 1 {
			return false, errors.New("ipv6 enable")
		}
		if c.IPv6Nodes == nil {
			return false, errors.New("尚未保存IPv6设置，请先配置地址并选择协议")
		}
		if err := configureIPv6Nodes(c, c.IPv6Nodes.Address, strings.Join(c.IPv6Nodes.Protocols, ","), deps); err != nil {
			return false, err
		}
	case "disable":
		if len(args) != 1 {
			return false, errors.New("ipv6 disable")
		}
		if !c.HasIPv6Nodes() {
			printIPv6Status(out, *c)
			return false, nil
		}
		c.IPv6Nodes.Enabled = false
	default:
		return false, errors.New("ipv6 status|configure|enable|disable")
	}
	return true, nil
}

func ipv6Menu(ctx context.Context, p paths, s *terminal.Session, out io.Writer, deps ipv6Deps) error {
	for {
		if ctx.Err() != nil {
			return terminal.ErrCanceled
		}
		fmt.Fprintln(out, "IPv6节点管理：1查看状态 2配置/选择协议 3启用已保存设置 4关闭 0返回")
		choice, err := s.ReadLine(ctx, "请选择: ", false)
		if err != nil {
			return err
		}
		if choice == "0" {
			return nil
		}
		if choice == "1" {
			if err := editWithIPv6Deps(ctx, p, []string{"ipv6", "status"}, out, deps); err != nil {
				return err
			}
			continue
		}
		args := []string{"ipv6"}
		switch choice {
		case "2":
			var current model.Config
			if err := p.admin(ctx, "GET", "/config", nil, &current); err != nil {
				return fmt.Errorf("请先完成IPv4初始化：%w", err)
			}
			addresses, err := deps.Addresses()
			if err != nil {
				return err
			}
			candidates := ipv6Candidates(addresses)
			for i, candidate := range candidates {
				fmt.Fprintf(out, "%d %s (%s)\n", i+1, candidate.Address, candidate.Interface)
			}
			if len(candidates) == 0 {
				fmt.Fprintln(out, "未检测到已分配公网IPv6；可手动填写核实，不会修改网卡或路由。")
			}
			address, err := s.ReadLine(ctx, "选择地址编号或输入本机公网IPv6（0返回）: ", false)
			if err != nil {
				return err
			}
			if address == "0" {
				continue
			}
			if index, err := strconv.Atoi(address); err == nil {
				if index < 1 || index > len(candidates) {
					return errors.New("无效IPv6地址编号")
				}
				address = candidates[index-1].Address.String()
			}
			label := "IPv6协议 vless,ss,tuic,hy2,anytls（逗号分隔；首次必须选择）: "
			if current.IPv6Nodes != nil {
				label = "IPv6协议（逗号分隔；留空保留 " + strings.Join(current.IPv6Nodes.Protocols, ",") + "）: "
			}
			selection, err := s.ReadLine(ctx, label, false)
			if err != nil {
				return err
			}
			if selection == "" && current.IPv6Nodes != nil {
				selection = strings.Join(current.IPv6Nodes.Protocols, ",")
			}
			if _, err := parseIPv6Protocols(selection); err != nil {
				return err
			}
			candidate := current.Clone()
			if err := configureIPv6Nodes(&candidate, address, selection, deps); err != nil {
				return err
			}
			printIPv6Status(out, candidate)
			args = append(args, "configure", "--address", candidate.IPv6Nodes.Address, "--protocols", strings.Join(candidate.IPv6Nodes.Protocols, ","))
		case "3":
			var current model.Config
			if err := p.admin(ctx, "GET", "/config", nil, &current); err != nil {
				return err
			}
			if current.IPv6Nodes == nil {
				return errors.New("请先配置IPv6地址并显式选择协议")
			}
			printIPv6Status(out, current)
			args = append(args, "enable")
		case "4":
			var current model.Config
			if err := p.admin(ctx, "GET", "/config", nil, &current); err != nil {
				return err
			}
			printIPv6Status(out, current)
			args = append(args, "disable")
		default:
			fmt.Fprintln(out, "无效选项")
			continue
		}
		fmt.Fprintln(out, "协议启停独立；同协议端口、凭据、证书共用。明确地址监听转换可能短暂重建连接；请自行放行云安全组的IPv6端口。")
		answer, err := s.ReadLine(ctx, "输入 yes 提交，其他输入返回: ", false)
		if err != nil {
			return err
		}
		if answer != "yes" {
			continue
		}
		if err := editWithIPv6Deps(ctx, p, args, out, deps); err != nil {
			return err
		}
	}
}
