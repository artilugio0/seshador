package seshador

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"
)

const hkdfSecretIdInfo = "seshador/v1/hkdf/info/secret-id"
const hkdfEncryptionKeyInfo = "seshador/v1/hkdf/info/encryption-key"

type Receiver struct {
	dhPriv *ecdh.PrivateKey
	dhPub  *ecdh.PublicKey

	sigPriv ed25519.PrivateKey
	sigPub  ed25519.PublicKey

	sharedSecret   []byte
	vaultChallenge []byte
}

func NewReceiver(dhPriv *ecdh.PrivateKey, sigPriv ed25519.PrivateKey) *Receiver {
	return &Receiver{
		dhPriv:  dhPriv,
		dhPub:   dhPriv.PublicKey(),
		sigPriv: sigPriv,
		sigPub:  sigPriv.Public().(ed25519.PublicKey),
	}
}

func (r *Receiver) InitialMessage() []byte {
	return slices.Concat(r.dhPub.Bytes(), r.sigPub)
}

func (r *Receiver) ProcessOwnerMessage(msg []byte) error {
	ownerPubBytes := msg[:publicKeySize]
	vaultChallenge := msg[publicKeySize : publicKeySize+vaultChallengeSize]

	curve := ecdh.X25519()
	ownerPub, err := curve.NewPublicKey(ownerPubBytes)
	if err != nil {
		return fmt.Errorf("invalid owner public key: %w", err)
	}

	sharedSecret, err := r.dhPriv.ECDH(ownerPub)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}

	r.sharedSecret = sharedSecret
	r.vaultChallenge = vaultChallenge

	return nil
}

func (r *Receiver) RetrieveSecret(vaultClient VaultClient) ([]byte, error) {
	secretID, err := hkdf.Key(sha256.New, r.sharedSecret, nil, hkdfSecretIdInfo, secretIDSize)
	if err != nil {
		return nil, fmt.Errorf("could not derive secret id: %w", err)
	}

	timestamp := time.Now().Format(time.RFC3339)
	msg := slices.Concat([]byte("retrieve"), secretID, r.vaultChallenge, []byte(timestamp))
	sig := ed25519.Sign(r.sigPriv, msg)

	encryptedSecret, err := vaultClient.RetrieveSecret(secretID, msg, sig)
	if err != nil {
		return nil, err
	}

	encNonce := encryptedSecret[:encryptionNonceSize]
	ciphertext := encryptedSecret[encryptionNonceSize:]

	encKey, err := hkdf.Key(sha256.New, r.sharedSecret, nil, hkdfEncryptionKeyInfo, encryptionKeySize)
	if err != nil {
		return nil, fmt.Errorf("could not derive decryption key: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("could not initialize AES: %w", err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not initialize AES-GCM: %w", err)
	}

	plaintext, err := aesGcm.Open(nil, encNonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("secret decryption failed: %w", err)
	}

	return plaintext, nil
}
