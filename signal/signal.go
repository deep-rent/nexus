// Package signal provides utilities for handling operating system signals.
package signal

import (
	"os"
	"os/signal"
	"syscall"
)

// Shutdown sets up a channel to listen for gracious termination signals.
func Shutdown() <-chan os.Signal {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	return c
}
