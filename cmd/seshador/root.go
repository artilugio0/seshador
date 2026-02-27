package main

import "github.com/spf13/cobra"

const (
	version = "v0.1.0"
)

func newSeshadorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seshador",
		Short: "seshador -- Secrets Sharting Done Right",
		Long: `seshador is a tool that helps with sharing secrets,
in a secure way by encrypting the secrets with AES-GCM using
keys derived from ephemeral Diffie-Hellman key exchange.

There are three different parties involved, all of which can be
executed with this same CLI:
- owner: knows the secret to be shared
- receiver: receives the secret
- vault: stores the secret temporarely and sends it to the receiver
`,
	}

	cmd.AddCommand(newShareCommand())
	cmd.AddCommand(newReceiveCommand())
	cmd.AddCommand(newVaultCommand())

	cmd.Version = version
	return cmd
}
