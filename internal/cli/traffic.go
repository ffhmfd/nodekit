package cli

import (
	"context"
	"fmt"
	"io"
	"nodekit/internal/model"
	"nodekit/internal/terminal"
)

func trafficDescription(c model.Config) string {
	if c.EffectiveTrafficMultiplier() == 2 {
		return "2 倍（代理用量 × 2，收发合计估算）"
	}
	return "1 倍（原始代理用量）"
}

func trafficMenu(ctx context.Context, p paths, s *terminal.Session, out io.Writer) error {
	var c model.Config
	if err := p.admin(ctx, "GET", "/config", nil, &c); err != nil {
		return err
	}
	fmt.Fprintf(out, "当前流量计量: %s\n1 原始代理用量（1倍）\n2 代理用量 × 2（收发合计估算）\n0 返回\n切换对整个当前周期生效，额度保持原值。\n", trafficDescription(c))
	for {
		choice, err := s.ReadLine(ctx, "选择流量计量方式: ", false)
		if err != nil {
			return err
		}
		switch choice {
		case "0":
			return nil
		case "1", "2":
			return edit(ctx, p, []string{"config", "set", "traffic-multiplier", choice}, out)
		default:
			fmt.Fprintln(out, "请输入 1、2 或 0")
		}
	}
}
