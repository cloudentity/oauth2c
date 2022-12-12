package main

import (
	"fmt"
	"os"

	"github.com/cloudentity/oauth2c/cmd"
)

func main() {
	if err := cmd.NewOAuth2Cmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
