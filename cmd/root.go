package main

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	verbose bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "keycloak",
	Short: "keycloak is a tool that enables a gitops approach for secrets.",
	Long: `keycloak is a tool that enables a gitops approach for secrets.
	This tool takes in a private key, a secrets file, decrypts the secrets using the private key and starts a child process with the secrets in the environment.`,
}

// execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}
