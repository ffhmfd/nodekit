package main

import (
	"context"
	"nodekit/internal/cli"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Interactive CLI scopes SIGINT to the active menu operation.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
