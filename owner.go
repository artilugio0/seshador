package seshador

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
)

type Owner struct {
	dhPriv          *ecdh.PrivateKey
	sharedSecret    []byte
	secretID        []byte
	encryptionNonce []byte
	vaultChallenge  []byte
	receiverSigPub  []byte
}

func NewOwner(dhPriv *ecdh.PrivateKey) *Owner {
	return &Owner{
		dhPriv: dhPriv,
	}
}

func (o *Owner) ProcessReceiverMessage(msg []byte) error {
	recPubBytes := msg[:32]
	o.receiverSigPub = msg[32:64]

	curve := ecdh.X25519()
	recPub, err := curve.NewPublicKey(recPubBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	sharedSecret, err := o.dhPriv.ECDH(recPub)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}
	o.sharedSecret = sharedSecret

	return nil
}

func (o *Owner) StoreSecret(secret []byte, vaultClient VaultClient) error {
	secretID, err := hkdf.Key(sha256.New, o.sharedSecret, nil, hkdfSecretIdInfo, 32)
	if err != nil {
		return fmt.Errorf("could not derive secret id: %w", err)
	}
	o.secretID = secretID

	encKey, err := hkdf.Key(sha256.New, o.sharedSecret, nil, hkdfEncryptionKeyInfo, 32)
	if err != nil {
		return fmt.Errorf("could not derive decryption key: %w", err)
	}

	o.encryptionNonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, o.encryptionNonce); err != nil {
		return fmt.Errorf("could not generate the encryption nonce: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("could not initialize AES: %w", err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("could not initialize AES-GCM: %w", err)
	}

	ciphertext := aesGcm.Seal(nil, o.encryptionNonce, secret, nil)
	ciphertext = slices.Concat(o.encryptionNonce, ciphertext)

	o.vaultChallenge, err = vaultClient.StoreSecret(secretID, o.receiverSigPub, ciphertext)
	if err != nil {
		return fmt.Errorf("could not store secret in the vault: %w", err)
	}

	return nil
}

func (o *Owner) MessageToReceiver() []byte {
	message := slices.Concat(o.dhPriv.PublicKey().Bytes(), o.vaultChallenge)
	return message
}
