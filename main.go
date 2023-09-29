package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudentity/oauth2c/cmd"
	"github.com/pterm/pterm"
)

func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		pterm.Error.Println("Interrupted")
		os.Exit(1)
	}()
}

func main() {
	if err := cmd.NewOAuth2Cmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
