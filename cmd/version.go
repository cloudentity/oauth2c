package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version",
	Run: func(cmd *cobra.Command, args []string) {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Sum != "" {
			fmt.Println(info)
		} else {
			fmt.Println("unknown")
		}
	},
}
