package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/artilugio0/seshador"
)

const hkdfSecretIdInfo = "seshador/v1/hkdf/info/secret-id"
const hkdfEncryptionKeyInfo = "seshador/v1/hkdf/info/encryption-key"

func main() {
	secret := "this is a secret string"

	ownerReceiverChan := make(chan []byte)
	vaultChan := make(chan []byte)
	vaultClient := &VaultClientFake{vaultChan}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		receiver(ownerReceiverChan, vaultClient)
	}()

	go func() {
		defer wg.Done()
		owner(secret, ownerReceiverChan, vaultClient)
	}()

	go func() {
		defer wg.Done()
		vault(vaultChan)
	}()

	wg.Wait()
}

func receiver(owner chan []byte, vaultClient seshador.VaultClient) {
	_, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	curve := ecdh.X25519()
	recPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	rec := seshador.NewReceiver(recPriv, sigPriv)
	initialMessage := rec.InitialMessage()

	fmt.Println("[Receiver] sending initial message to secret owner")
	owner <- initialMessage

	msg := <-owner
	if err := rec.ProcessOwnerMessage(msg); err != nil {
		panic(err)
	}
	fmt.Println("[Receiver] received owner public key and vault challenge")

	fmt.Println("[Receiver] retrieving secret from vault")
	plaintextSecret, err := rec.RetrieveSecret(vaultClient)
	if err != nil {
		panic(err)
	}

	fmt.Println("[Receiver] plaintext secret:", string(plaintextSecret))
}

func owner(secret string, receiver chan []byte, vaultClient seshador.VaultClient) {
	curve := ecdh.X25519()
	sendPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	owner := seshador.NewOwner(sendPriv)

	messageFromReceiver := <-receiver
	fmt.Println("[Owner] received initial message from receiver")
	if err := owner.ProcessReceiverMessage(messageFromReceiver); err != nil {
		panic(err)
	}

	fmt.Println("[Owner] storing secret in vault")
	if err := owner.StoreSecret([]byte(secret), vaultClient); err != nil {
		panic(err)
	}

	messageToReceiver := owner.MessageToReceiver()

	fmt.Println("[Owner] sending public key and challenge to receiver")
	receiver <- messageToReceiver
}

func vault(ioChan chan []byte) {
	vault := seshador.NewVault(&KVS{map[string]*seshador.SecretEntry{}})

	secretID := <-ioChan
	recSigPubBytes := <-ioChan
	ciphertext := <-ioChan
	fmt.Println("[Vault] received a secret store request from owner")

	challenge, err := vault.StoreSecret(secretID, recSigPubBytes, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println("[Vault] secret stored. Sending challenge to owner")
	ioChan <- challenge

	recSecretID := <-ioChan
	recMessage := <-ioChan
	recSig := <-ioChan
	fmt.Println("[Vault] received a secret retrieve request from receiver")

	retrievedSecret, err := vault.RetrieveSecret(recSecretID, recMessage, recSig)
	if err != nil {
		panic(err)
	}

	fmt.Println("[Vault] sending secret to receiver")
	ioChan <- retrievedSecret
}

type VaultClientFake struct {
	vaultChan chan []byte
}

func (vcf *VaultClientFake) RetrieveSecret(secretID, msg, sig []byte) ([]byte, error) {
	vcf.vaultChan <- secretID
	vcf.vaultChan <- msg
	vcf.vaultChan <- sig

	secret := <-vcf.vaultChan

	return secret, nil
}

func (vcf *VaultClientFake) StoreSecret(secretID, recPub, ciphertext []byte) ([]byte, error) {
	vcf.vaultChan <- secretID
	vcf.vaultChan <- recPub
	vcf.vaultChan <- ciphertext

	challenge := <-vcf.vaultChan

	return challenge, nil
}

type KVS struct {
	values map[string]*seshador.SecretEntry
}

func (kvs *KVS) Put(key []byte, value seshador.SecretEntry) error {
	kvs.values[string(key)] = &value
	return nil
}

func (kvs *KVS) Get(key []byte) (*seshador.SecretEntry, error) {
	se := kvs.values[string(key)]
	return se, nil
}

func (kvs *KVS) Delete(key []byte) error {
	kvs.values[string(key)] = nil
	return nil
}
