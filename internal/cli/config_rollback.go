package cli

import (
	"context"
	"errors"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"time"
)

func abortConfigChange(p paths, old, next model.Config, undoRules, undoRequirement func() error) error {
	if old.IPv6Nodes != nil || next.IPv6Nodes != nil {
		// GET /config may still show the old committed revision after a failed
		// rollback. It does not establish that the candidate's sockets/journal
		// are gone, so keep both guards until the manager confirms no operation.
		probe, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var status store.Record
		if err := p.admin(probe, "GET", "/status", nil, &status); err != nil {
			return errors.Join(err, cloudflare.ErrUncertain)
		}
		if status.OperationPhase != "" || status.Operation != nil {
			return errors.Join(errors.New("IPv6配置尚有未完成操作；请用当前版本恢复后再清理能力及防火墙记录"), cloudflare.ErrUncertain)
		}
	}
	if err := undoRules(); err != nil {
		return err
	}
	return undoRequirement()
}
