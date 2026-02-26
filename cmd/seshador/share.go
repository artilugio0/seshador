package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/artilugio0/seshador"
	"github.com/spf13/cobra"
)

const (
	shareVaultURLDefault = ""
)

func newShareCommand() *cobra.Command {
	var (
		vaultURL string
	)

	cmd := &cobra.Command{
		Use:   "share",
		Short: "share a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secret := args[0]

			fmt.Print("Enter the code the secret receiver sent you: ")
			reader := bufio.NewReader(os.Stdin)
			receiverMsgStr, err := reader.ReadString('\n')
			if err != nil {
				return err
			}

			receiverMsg, err := base64.StdEncoding.DecodeString(receiverMsgStr)
			if err != nil {
				return err
			}

			curve := ecdh.X25519()
			dhPriv, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}

			owner := seshador.NewOwner(dhPriv)

			if err := owner.ProcessReceiverMessage(receiverMsg); err != nil {
				return err
			}

			vaultClient := seshador.NewVaultClientHTTP(vaultURL)

			if err := owner.StoreSecret([]byte(secret), vaultClient); err != nil {
				return err
			}

			msg := owner.MessageToReceiver()
			fmt.Println("Send the following code to the secret receiver (it is not secret, anyone can see it):")
			fmt.Println(base64.StdEncoding.EncodeToString(msg))

			return nil
		},
	}

	cmd.Flags().StringVarP(&vaultURL, "vault-url", "u", receiveVaultURLDefault, "Vault server URL")
	if err := cmd.MarkFlagRequired("vault-url"); err != nil {
		panic(err)
	}

	return cmd
}
