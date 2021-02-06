// Package main defines and runs a command, used to find network attacks
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dfreilich/guardicore-policy-engine"
)

func main(){
	// Removes timestamps from the beginning of each log line, to make it clearer to the reader.
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	cmd := engine.NewRunCommand()
	// Executes the command, together with a context which can read and respond to an interrupt signal (control+C)
	if err := cmd.ExecuteContext(createCancellableContext()); err != nil {
		os.Exit(1)
	}
}

func createCancellableContext() context.Context {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-signals
		cancel()
	}()

	return ctx
}
