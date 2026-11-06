package cli

import (
	"context"
	"fmt"
	"io"
	"nodekit/internal/model"
	"nodekit/internal/terminal"
	"strconv"
)

func protocolMenu(ctx context.Context, p paths, s *terminal.Session, out io.Writer, deps ipv6Deps) error {
	selected := -1
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var c model.Config
		if err := p.admin(ctx, "GET", "/config", nil, &c); err != nil {
			return err
		}
		fmt.Fprintln(out, "协议管理（原入口）")
		for i, protocol := range c.Protocols {
			state := "已停用"
			if protocol.Enabled {
				state = "已启用"
			}
			fmt.Fprintf(out, "%d %s：%s，端口%d\n", i+1, model.ProtocolLabel(protocol.Type), state, protocol.Port)
		}
		if c.IPv6Nodes != nil {
			printIPv6Status(out, c)
			fmt.Fprintln(out, "原入口启停不改变IPv6选择；附加IPv6启停请使用主菜单24。同协议共用端口、凭据及名称，修改会同时影响两类入口。")
		}
		if selected < 0 || selected >= len(c.Protocols) {
			choice, err := s.ReadLine(ctx, "选择协议（0返回主菜单）: ", false)
			if err != nil {
				return err
			}
			if choice == "0" {
				return nil
			}
			n, err := strconv.Atoi(choice)
			if err != nil || n < 1 || n > len(c.Protocols) {
				fmt.Fprintln(out, "无效协议编号，请重试")
				continue
			}
			selected = n - 1
		}
		protocol := c.Protocols[selected]
		fmt.Fprintf(out, "%s：1启用 2停用 3修改端口 4更换凭据 5修改名称 6恢复自动名称 0返回\n", model.ProtocolLabel(protocol.Type))
		choice, err := s.ReadLine(ctx, "选择操作: ", false)
		if err != nil {
			return err
		}
		if choice == "0" {
			selected = -1
			continue
		}
		action := map[string]string{"1": "enable", "2": "disable", "3": "port", "4": "rotate", "5": "name", "6": "name"}[choice]
		if action == "" {
			fmt.Fprintln(out, "无效操作编号，请重试")
			continue
		}
		args := []string{"protocol", action, protocol.Type}
		if choice == "3" || choice == "5" {
			for {
				prompt := "完整显示名称（保留内部空格，0返回）: "
				if choice == "3" {
					prompt = fmt.Sprintf("当前端口%d，新端口（1024–65535，0返回）: ", protocol.Port)
				}
				value, err := s.ReadLine(ctx, prompt, false)
				if err != nil {
					return err
				}
				if value == "0" {
					break
				}
				candidate := c.Clone()
				if choice == "3" {
					port, err := strconv.Atoi(value)
					if err != nil || port < 1024 || port > 65535 {
						fmt.Fprintln(out, "请输入1024–65535的端口，或0返回")
						continue
					}
					candidate.Protocols[selected].Port = port
				} else {
					if value == "" {
						fmt.Fprintln(out, "名称不能为空；恢复自动名称请选择操作6")
						continue
					}
					candidate.Protocols[selected].Name = value
					if value == "auto" {
						candidate.Protocols[selected].Name = ""
					}
				}
				// Retry only local input validation. Commit failures may have applied
				// already and must return to the caller without an automatic retry.
				if err := candidate.Validate(); err != nil {
					fmt.Fprintf(out, "输入无效：%v，请重试\n", err)
					continue
				}
				args = append(args, value)
				break
			}
			if len(args) == 3 {
				continue
			}
		} else if choice == "6" {
			args = append(args, "auto")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := editWithIPv6Deps(ctx, p, args, out, deps); err != nil {
			return err
		}
		fmt.Fprintln(out, "操作成功，请在客户端刷新订阅。")
		selected = -1
	}
}
