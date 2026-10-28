package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

func purgeSummary(ctx context.Context, p paths, out io.Writer) error {
	m, err := loadHost(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(out, "未完成初始化：将清理归属本项目的安装文件和标准Token文件。")
			return nil
		}
		return err
	}
	if m.PurgePhase != "" {
		fmt.Fprintln(out, "继续卸载阶段:", m.PurgePhase)
	}
	if len(m.DNSRecords) > 0 {
		for _, r := range m.DNSRecords {
			fmt.Fprintf(out, "DNS %s %s → %s\n", r.Record.Type, r.Record.Name, r.Record.Content)
		}
	} else {
		if c, err := rootConfig(ctx, p); err == nil {
			fmt.Fprintf(out, "旧安装将核对当前域名 %s 对应的 %s 记录，匹配后删除。\n", c.Domain, c.Address)
		}
	}
	fmt.Fprintln(out, "删除项目服务、程序、账户、配置、证书、用量及标准Token文件。自选外部Token源文件保留。")
	return nil
}
