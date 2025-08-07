package graceful

import (
	"os"
	"os/signal"
	"syscall"
)

func MakeSigintChan() chan os.Signal {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	return sigCh
}
