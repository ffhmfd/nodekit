package cli

import (
	"context"
	"encoding/json"
	"errors"
	"nodekit/internal/model"
	"os/exec"
	"time"
)

type capabilities struct {
	SubscriptionModes []string `json:"subscription_modes"`
}

func checkReleaseCompatibility(ctx context.Context, c model.Config, binary string) error {
	if c.EffectiveSubscriptionMode() == "direct" {
		return nil
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(probe, binary, "capabilities").Output()
	var result capabilities
	if err == nil && json.Unmarshal(data, &result) == nil {
		for _, mode := range result.SubscriptionModes {
			if mode == c.EffectiveSubscriptionMode() {
				return nil
			}
		}
	}
	return errors.New("目标程序不支持当前订阅模式；如需降级，请先显式切回 direct")
}
