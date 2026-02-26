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
	vaultSeverAddrDefault = ":8080"
)

func newVaultCommand() *cobra.Command {
	var (
		serverAddr string
	)

	cmd := &cobra.Command{
		Use:   "vault",
		Short: "run a vault server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			vault := seshador.NewVault(newKVS())
			vaultServer := seshador.NewVaultServer(vault)

			log.Printf("Vault server running on %s", serverAddr)
			if err := http.ListenAndServe(serverAddr, vaultServer); err != nil {
				return fmt.Errorf("server execution ended: %v", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&serverAddr, "listen", "l", vaultSeverAddrDefault, "Server address")

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

	kvs.values[string(key)] = nil
	return nil
}
