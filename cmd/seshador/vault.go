package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/artilugio0/seshador"
	"github.com/spf13/cobra"
)

const (
	vaultSeverAddrDefault = ":8443"
)

func newVaultCommand() *cobra.Command {
	var (
		serverAddr    string
		tlsCert       string
		tlsKey        string
		insecureNoTLS bool
	)

	cmd := &cobra.Command{
		Use:   "vault",
		Short: "run a vault server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			vault := seshador.NewVault(newKVS())
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

	cmd.Flags().StringVarP(&serverAddr, "listen", "l", vaultSeverAddrDefault, "Server address")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate file (PEM)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS private key file (PEM)")
	cmd.Flags().BoolVar(&insecureNoTLS, "insecure-no-tls", false, "Run without TLS — INSECURE")

	return cmd
}

type KVS struct {
	mutex  sync.Mutex
	values map[string]*seshador.SecretEntry
}

func newKVS() *KVS {
	return &KVS{
		mutex:  sync.Mutex{},
		values: map[string]*seshador.SecretEntry{},
	}
}

func (kvs *KVS) Put(key []byte, value seshador.SecretEntry) error {
	kvs.mutex.Lock()
	defer kvs.mutex.Unlock()

	kvs.values[string(key)] = &value
	return nil
}

func (kvs *KVS) Get(key []byte) (*seshador.SecretEntry, error) {
	kvs.mutex.Lock()
	defer kvs.mutex.Unlock()

	se := kvs.values[string(key)]
	return se, nil
}

func (kvs *KVS) Delete(key []byte) error {
	kvs.mutex.Lock()
	defer kvs.mutex.Unlock()

	delete(kvs.values, string(key))
	return nil
}
