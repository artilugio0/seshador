package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/artilugio0/seshador"
	"github.com/spf13/cobra"
)

const (
	shareInsecureNoTLSDefault         = false
	shareTLSCACertDefault             = ""
	shareTLSInsecureSkipVerifyDefault = false
	shareVaultURLDefault              = ""
)

func newShareCommand() *cobra.Command {
	var (
		insecureNoTLS         bool
		tlsCACert             string
		tlsInsecureSkipVerify bool
		vaultURL              string
	)

	cmd := &cobra.Command{
		Use:   "share",
		Short: "share a secret",
		Args:  cobra.ExactArgs(1),
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

			secret := args[0]

			fmt.Print("Enter the code the secret receiver sent you: ")
			reader := bufio.NewReader(os.Stdin)
			receiverMsgStr, err := reader.ReadString('\n')
			if err != nil {
				return err
			}

			receiverMsg, err := base64.URLEncoding.DecodeString(receiverMsgStr)
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

			transport, err := newHTTPTransport(tlsCACert, tlsInsecureSkipVerify)
			if err != nil {
				return err
			}

			vaultClient := seshador.NewVaultClientHTTP(vaultURL).
				WithTransport(transport)

			if err := owner.StoreSecret([]byte(secret), vaultClient); err != nil {
				return err
			}

			msg := owner.MessageToReceiver()
			fmt.Println("Send the following code to the secret receiver (it is not secret, anyone can see it):")
			fmt.Println(base64.URLEncoding.EncodeToString(msg))

			return nil
		},
	}

	cmd.Flags().BoolVar(&insecureNoTLS, "insecure-no-tls", shareInsecureNoTLSDefault, "Do not use TLS for the communication with the vault server — INSECURE")
	cmd.Flags().BoolVar(&tlsInsecureSkipVerify, "tls-insecure-skip-verify", shareTLSInsecureSkipVerifyDefault, "Skip server certificate verification — INSECURE")
	cmd.Flags().StringVar(&tlsCACert, "tls-ca-cert", shareTLSCACertDefault, "Custom CA certificate file (PEM)")
	cmd.Flags().StringVarP(&vaultURL, "vault-url", "u", receiveVaultURLDefault, "Vault server URL")

	if err := cmd.MarkFlagRequired("vault-url"); err != nil {
		panic(err)
	}

	return cmd
}

func newHTTPTransport(tlsCACert string, tlsInsecureSkipVerify bool) (*http.Transport, error) {
	if tlsCACert == "" && !tlsInsecureSkipVerify {
		return http.DefaultTransport.(*http.Transport).Clone(), nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if tlsInsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
		log.Println("WARNING: TLS verification disabled (--tls-insecure-skip-verify)")
	}

	if tlsCACert != "" {
		caCert, err := os.ReadFile(tlsCACert)
		if err != nil {
			return nil, fmt.Errorf("Failed to read CA cert: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("Failed to append CA cert to pool")
		}
		tlsConfig.RootCAs = caPool
	}

	return &http.Transport{
		TLSClientConfig: tlsConfig,
	}, nil
}
