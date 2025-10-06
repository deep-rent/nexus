// Package signal provides utilities for handling operating system signals.
package signal

import (
	"os"
	"syscall"
)

// Shutdown lists signals that should trigger a graceful shutdown.
func Shutdown() []os.Signal {
	return []os.Signal{
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGKILL,
	}
}
