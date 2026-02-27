package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/artilugio0/seshador"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/spf13/cobra"
)

const (
	vaultSeverAddrDefault = ":8443"
	vaultStorageDefault   = "memory://"
)

func newVaultCommand() *cobra.Command {
	var (
		insecureNoTLS bool
		serverAddr    string
		storage       string
		tlsCert       string
		tlsKey        string
	)

	cmd := &cobra.Command{
		Use:   "vault",
		Short: "run a vault server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var kvs seshador.KeyValueStore

			if storage == "" || storage == "memory://" || storage == "memory" {
				kvs = seshador.NewKVSMemory()
			} else if strings.HasPrefix(storage, "dynamodb://") {
				rest := strings.TrimPrefix(storage, "dynamodb://")
				parts := strings.SplitN(rest, "/", 2)
				if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
					return fmt.Errorf("invalid DynamoDB URI format. Expected: dynamodb://region/table-name")
				}

				region := parts[0]
				tableName := parts[1]

				cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
				if err != nil {
					return fmt.Errorf("failed to load AWS config for region %s: %w", region, err)
				}

				dynamoDBClient := dynamodb.NewFromConfig(cfg, func(opts *dynamodb.Options) {
					if tableName == "local-development" {
						opts.BaseEndpoint = aws.String("http://localhost:8000")
					}
				})

				kvs = seshador.NewKVSDynamoDB(dynamoDBClient, tableName)

				log.Printf("Using DynamoDB storage: %s", storage)
			} else {
				return fmt.Errorf("unsupported storage URI scheme: %s", storage)
			}

			vault := seshador.NewVault(kvs)
			vaultServer := seshador.NewVaultServer(vault)

			if !insecureNoTLS {
				if tlsCert == "" || tlsKey == "" {
					return fmt.Errorf("TLS is required by default. Provide --tls-cert and --tls-key, or use --insecure-no-tls for plaintext HTTP (not recommended)")
				}
				log.Printf("Vault server running on %s", serverAddr)
				return http.ListenAndServeTLS(serverAddr, tlsCert, tlsKey, vaultServer)
			}

			// Insecure mode
			log.Println("WARNING: Running WITHOUT TLS — all communication is plaintext and unauthenticated!")
			log.Printf("Vault server running on %s", serverAddr)
			return http.ListenAndServe(serverAddr, vaultServer)
		},
	}

	cmd.Flags().StringVar(&storage, "storage", vaultStorageDefault, "Storage backend URI (memory:// or dynamodb://region/table)")
	cmd.Flags().StringVarP(&serverAddr, "listen", "l", vaultSeverAddrDefault, "Server address")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate file (PEM)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS private key file (PEM)")
	cmd.Flags().BoolVar(&insecureNoTLS, "insecure-no-tls", false, "Run without TLS — INSECURE")

	return cmd
}
