package httpapi

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
)

type peerUIDKey struct{}

// PeerContext trusts kernel credentials, never a caller-provided HTTP header.
func PeerContext(ctx context.Context, conn net.Conn) context.Context {
	uid := -1
	if socket, ok := conn.(*net.UnixConn); ok {
		if raw, err := socket.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
					uid = int(cred.Uid)
				}
			})
		}
	}
	return context.WithValue(ctx, peerUIDKey{}, uid)
}

func RootPeer(ctx context.Context) bool {
	uid, ok := ctx.Value(peerUIDKey{}).(int)
	return ok && uid == 0
}
