package cmd

import (
	"github.com/spf13/cobra"
)

func NewVersionCmd(version, commit, date string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display version",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("oauth2c version %s (commit %s, built at %s)\n", version, commit, date)
		},
	}
}
