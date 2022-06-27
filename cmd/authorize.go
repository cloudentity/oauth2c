package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "authorize",
	Short: "Obtain authorization from the resource owner via user-agent redirection",
	Run: func(cmd *cobra.Command, args []string) {
	},
}
