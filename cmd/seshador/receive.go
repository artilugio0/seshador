package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"

	"github.com/artilugio0/seshador"
	"github.com/spf13/cobra"
)

const (
	receiveInsecureNoTLSDefault         = false
	receiveTLSCACertDefault             = ""
	receiveTLSInsecureSkipVerifyDefault = false
	receiveVaultURLDefault              = ""
)

func newReceiveCommand() *cobra.Command {
	var (
		insecureNoTLS         bool
		tlsCACert             string
		tlsInsecureSkipVerify bool
		vaultURL              string
	)

	cmd := &cobra.Command{
		Use:   "receive",
		Short: "receive a secret",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pVaultURL, err := url.Parse(vaultURL)
			if err != nil {
				return err
			}

			if pVaultURL.Scheme != "https" && !insecureNoTLS {
				return fmt.Errorf("The vault URL scheme is '%s', but TLS is required by default. "+
					"If this was not a mistake, use the --insecure-no-tls for plaintext HTTP (not recommended)",
					pVaultURL.Scheme)
			}

			curve := ecdh.X25519()
			dhPriv, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}

			_, sigPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}

			receiver := seshador.NewReceiver(dhPriv, sigPriv)

			msg := receiver.InitialMessage()

			fmt.Println("Send the following code to the owner of the secret (this code is not secret, anyone can see it):")
			fmt.Println(base64.URLEncoding.EncodeToString(msg))

			fmt.Print("\nEnter the code the owner of the secret sent you: ")
			reader := bufio.NewReader(os.Stdin)
			ownerMsgStr, err := reader.ReadString('\n')
			if err != nil {
				return err
			}

			ownerMsg, err := base64.URLEncoding.DecodeString(ownerMsgStr)
			if err != nil {
				return err
			}

			if err := receiver.ProcessOwnerMessage(ownerMsg); err != nil {
				return err
			}

			transport, err := newHTTPTransport(tlsCACert, tlsInsecureSkipVerify)
			if err != nil {
				return err
			}

			vaultClient := seshador.NewVaultClientHTTP(vaultURL).
				WithTransport(transport)

			secret, err := receiver.RetrieveSecret(vaultClient)
			if err != nil {
				return err
			}

			fmt.Println("\nSecret:")
			if _, err := os.Stdout.Write(secret); err != nil {
				return err
			}
			fmt.Println("")

			return nil
		},
	}

	cmd.Flags().BoolVar(&insecureNoTLS, "insecure-no-tls", shareInsecureNoTLSDefault, "Do not use TLS for the communication with the vault server — INSECURE")
	cmd.Flags().BoolVar(&tlsInsecureSkipVerify, "tls-insecure-skip-verify", receiveTLSInsecureSkipVerifyDefault, "Skip server certificate verification — INSECURE")
	cmd.Flags().StringVar(&tlsCACert, "tls-ca-cert", receiveTLSCACertDefault, "Custom CA certificate file (PEM)")
	cmd.Flags().StringVarP(&vaultURL, "vault-url", "u", receiveVaultURLDefault, "Vault server URL")

	if err := cmd.MarkFlagRequired("vault-url"); err != nil {
		panic(err)
	}

	return cmd
}
