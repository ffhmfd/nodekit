package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"nodekit/internal/platform"
	"nodekit/internal/terminal"
	"os"
	"path/filepath"
)

type setupContextKey struct{}

func setupCommand(ctx context.Context, p paths, args []string, in io.Reader, out io.Writer) error {
	resume := len(args) == 1 && args[0] == "--resume"
	if len(args) > 0 && !resume {
		return errors.New("setup [--resume]")
	}
	s := terminal.FromContext(ctx)
	if s == nil {
		s = terminal.New(in, out)
	}
	if !resume && !s.IsTTY() {
		return errors.New("初始化向导需要交互终端；非交互请使用 init 的显式参数")
	}
	if os.Geteuid() != 0 {
		return errors.New("初始化向导需要root")
	}
	draft := filepath.Join(p.Etc, "setup.json")
	var input setupInput
	if resume {
		b, err := platform.ReadPrivate(draft)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(b, &input); err != nil {
			return err
		}
	} else {
		if _, err := os.Stat(filepath.Join(p.Data, "state.db")); err == nil {
			return errors.New("已有配置；请使用管理菜单，旧安装接管DNS运行 nodekit dns adopt")
		}
		if _, err := os.Lstat(draft); err == nil {
			return errors.New("已有未完成向导；运行 nodekit setup --resume")
		}
		var err error
		input, err = collectSetup(ctx, s, defaultWizardDeps())
		if err != nil {
			return err
		}
		for _, dir := range []string{p.Etc, p.Opt} {
			if err = platform.Claim(dir); err != nil {
				return err
			}
		}
		lock, err := operationLock(p)
		if err != nil {
			return err
		}
		// Recheck after collecting input: a second wizard may have committed
		// its draft while this one was waiting for user input.
		if _, err = os.Lstat(draft); err == nil {
			lock.Close()
			return errors.New("another setup draft already exists; use setup --resume")
		}
		standard := filepath.Join(p.Root, "root/nodekit-cloudflare.token")
		if err = platform.WritePrivate(standard, []byte(input.Token)); err != nil {
			lock.Close()
			return err
		}
		input.Token = ""
		input.TokenPath = standard
		if err = writeJSON(draft, input); err != nil {
			lock.Close()
			return err
		}
		lock.Close()
	}
	if err := input.Config.Validate(); err != nil {
		return err
	}
	configFile := filepath.Join(p.Etc, "setup-config.json")
	if err := writeJSON(configFile, input.Config); err != nil {
		return err
	}
	ctx = context.WithValue(ctx, setupContextKey{}, input)
	initArgs := []string{"--config", configFile, "--managed-dns", "--dns-zone", input.ZoneID, "--email", input.Email, "--token-file", input.TokenPath, "--firewall", input.Firewall}
	if err := initialize(ctx, p, initArgs, in, out); err != nil {
		return err
	}
	for _, file := range []string{draft, configFile} {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	fmt.Fprintln(out, "向导完成。运行 nodekit 打开管理菜单。")
	return nil
}
