package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/artilugio0/seshador"
)

func main() {
	args := os.Args
	if len(args) <= 1 {
		runVaultServer()
		return
	}

	switch args[1] {
	case "vault":
		runVaultServer()
	case "receiver":
		runReceiver()
	case "owner":
		runOwner()
	}
}

func runVaultServer() {
	vault := seshador.NewVault(newKVS())
	vaultServer := seshador.NewVaultServer(vault)

	serverAddr := ":8080"
	log.Printf("Vault server running on %s", serverAddr)
	http.ListenAndServe(serverAddr, vaultServer)
}

func runReceiver() {
	curve := ecdh.X25519()
	dhPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	_, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	receiver := seshador.NewReceiver(dhPriv, sigPriv)

	msg := receiver.InitialMessage()

	fmt.Println("Send the following code to the secret owner (it is not secret, anyone can see it):")
	fmt.Println(base64.StdEncoding.EncodeToString(msg))

	fmt.Print("\nEnter the code the secret owner sent you: ")
	reader := bufio.NewReader(os.Stdin)
	ownerMsgStr, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	ownerMsg, err := base64.StdEncoding.DecodeString(ownerMsgStr)
	if err != nil {
		panic(err)
	}

	if err := receiver.ProcessOwnerMessage(ownerMsg); err != nil {
		panic(err)
	}

	vaultClient := seshador.NewVaultClientHTTP("http://localhost:8080")
	secret, err := receiver.RetrieveSecret(vaultClient)
	if err != nil {
		panic(err)
	}

	fmt.Println("Secret:")
	fmt.Println(string(secret))
}

func runOwner() {
	if len(os.Args) != 3 {
		panic("expected secret as an argument")
	}
	secret := os.Args[2]

	fmt.Print("Enter the code the secret receiver sent you: ")
	reader := bufio.NewReader(os.Stdin)
	receiverMsgStr, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	receiverMsg, err := base64.StdEncoding.DecodeString(receiverMsgStr)
	if err != nil {
		panic(err)
	}

	curve := ecdh.X25519()
	dhPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	owner := seshador.NewOwner(dhPriv)

	if err := owner.ProcessReceiverMessage(receiverMsg); err != nil {
		panic(err)
	}

	vaultClient := seshador.NewVaultClientHTTP("http://localhost:8080")

	if err := owner.StoreSecret([]byte(secret), vaultClient); err != nil {
		panic(err)
	}

	msg := owner.MessageToReceiver()
	fmt.Println("Send the following code to the secret receiver (it is not secret, anyone can see it):")
	fmt.Println(base64.StdEncoding.EncodeToString(msg))
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
