package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/terminal"
	"os"
	"path/filepath"
)

// Diagnostic metadata only; never persist command arguments, tokens or errors
// returned by external APIs. The owning operation holds operation.lock.
type installProgress struct {
	Stage    string `json:"stage"`
	Complete bool   `json:"complete"`
}

func saveInstallProgress(p paths, stage string, complete bool) error {
	return writeJSON(filepath.Join(p.Etc, "install-progress.json"), installProgress{stage, complete})
}

type installationFailure struct {
	stage, recovery string
	cause           error
}

func (e *installationFailure) Error() string {
	return fmt.Sprintf("安装未完成；失败阶段：%s\n原因：%v\n恢复方式：%s", e.stage, e.cause, e.recovery)
}
func (e *installationFailure) Unwrap() error { return e.cause }

func installationRecovery(p paths) string {
	var recovery string
	if _, err := os.Stat(filepath.Join(p.Data, "state.db")); err == nil {
		recovery = "修复原因后运行 nodekit resume；如需手动管理防火墙，运行 nodekit resume --firewall manual"
	} else if _, err := os.Stat(filepath.Join(p.Etc, "setup.json")); err == nil {
		recovery = "修复原因后运行 nodekit setup --resume（菜单23）；如需手动管理防火墙，运行 nodekit setup --resume --firewall manual"
	} else {
		recovery = "修复原因后重新运行 nodekit setup 或原 nodekit init 命令；自动防火墙不支持时选择 manual / --firewall manual"
	}
	if m, err := loadHost(p); err == nil && m.DNSOperation != nil {
		recovery = "先运行 nodekit dns recover 恢复未完成DNS操作；" + recovery
	}
	return recovery
}

func describeInstallFailure(p paths, stage string, err error) error {
	var existing *installationFailure
	if errors.As(err, &existing) {
		return err
	}
	return &installationFailure{stage, installationRecovery(p), err}
}

func checkInstallFirewall(ctx context.Context, c model.Config, mode string) error {
	return checkRecoveryFirewall(ctx, c, mode, hostManifest{}, platform.Firewall{})
}

func checkRecoveryFirewall(ctx context.Context, c model.Config, mode string, m hostManifest, f platform.Firewall) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if mode == "manual" {
		return nil
	}
	if mode != "auto" {
		return errors.New("防火墙模式必须是 auto 或 manual")
	}
	desired := platform.Bindings(c)
	var err error
	if m.PendingFirewall != nil {
		known := bindingsUnion(m.Firewall, bindingsUnion(m.PendingFirewall.Old, m.PendingFirewall.New))
		restore := m.PendingFirewall.Revision == c.Revision
		if restore {
			desired = firewallRecoveryTarget(m.PendingFirewall.Old, desired)
		}
		err = f.PreflightRecovery(ctx, known, desired, restore)
	} else {
		err = f.Preflight(ctx, desired)
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("防火墙预检失败，当前自动管理不支持或不可用；请选择 manual（命令行 --firewall manual），自行放行节点及订阅端口：%w", err)
	}
	return nil
}

// A preflight failure must not create an installation. If the installer already
// owns these directories, retain just the diagnostic under its operation lock.
func rememberPreflightFailure(p paths) {
	if owned(p.Etc) != nil || owned(p.Opt) != nil {
		return
	}
	lock, err := operationLock(p)
	if err != nil {
		return
	}
	defer lock.Close()
	_ = saveInstallProgress(p, "防火墙预检", false)
}

func selectSetupFirewall(ctx context.Context, s *terminal.Session, c model.Config, mode string) (string, error) {
	err := checkInstallFirewall(ctx, c, mode)
	if err == nil {
		return mode, nil
	}
	if ctx.Err() != nil {
		return mode, ctx.Err()
	}
	if mode != "auto" || !s.IsTTY() {
		return mode, err
	}
	s.Printf("%v\n", err)
	answer, readErr := s.ReadLine(ctx, "输入 manual 改为手动放行端口并继续，其他输入取消: ", false)
	if readErr != nil {
		return mode, readErr
	}
	if answer != "manual" {
		return mode, terminal.ErrCanceled
	}
	return "manual", nil
}

func incompleteInstallation(p paths) error {
	stage := ""
	b, err := platform.ReadPrivate(filepath.Join(p.Etc, "install-progress.json"))
	if err == nil {
		var progress installProgress
		if err = json.Unmarshal(b, &progress); err != nil {
			return fmt.Errorf("无法读取安装阶段：%w", err)
		}
		if !progress.Complete {
			stage = progress.Stage
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if stage == "" {
		m, err := loadHost(p)
		if err == nil && m.InitPhase != "" && m.InitPhase != "ready" {
			stage = map[string]string{"prepared": "准备安装", "configured": "配置已写入，服务尚未就绪", "retained": "保留数据卸载，等待恢复"}[m.InitPhase]
			if stage == "" {
				stage = m.InitPhase
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if stage == "" {
		if _, err := os.Stat(filepath.Join(p.Data, "state.db")); errors.Is(err, os.ErrNotExist) {
			stage = "尚未初始化"
		} else if err != nil {
			return err
		}
	}
	if stage == "" {
		return nil
	}
	return fmt.Errorf("安装未完成；当前阶段：%s\n恢复方式：%s", stage, installationRecovery(p))
}
