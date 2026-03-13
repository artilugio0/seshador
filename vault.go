package seshador

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"time"
)

type Vault struct {
	kvs KeyValueStore
}

func NewVault(kvs KeyValueStore) *Vault {
	return &Vault{
		kvs: kvs,
	}
}

func (v *Vault) StoreSecret(secretID, recPub, encryptedSecret []byte) ([]byte, error) {
	existingEntry, err := v.kvs.Get(secretID)
	if err != nil {
		return nil, fmt.Errorf("could not get secret entry: %w", err)
	}

	if existingEntry != nil {
		return nil, errors.New("secret id already in use")
	}

	challenge := make([]byte, vaultChallengeSize)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		return nil, fmt.Errorf("could not create random challenge value: %w", err)
	}

	challengeHash := sha256.Sum256(challenge)

	secretEntry := SecretEntry{
		Expiration:      time.Now().Add(24 * time.Hour),
		ChallengeHash:   challengeHash[:],
		EncryptedSecret: encryptedSecret,
		ReceiverPubKey:  recPub, // raw Ed25519 pub key bytes; length already validated by caller
	}

	secretIDHash := sha256.Sum256(secretID)
	if err := v.kvs.Put(secretIDHash[:], secretEntry); err != nil {
		return nil, fmt.Errorf("could not store secret: %w", err)
	}

	return challenge, nil
}

func (v *Vault) RetrieveSecret(secretID, msg, sig []byte) ([]byte, error) {
	secretIDHash := sha256.Sum256(secretID)
	secretEntry, err := v.kvs.Get(secretIDHash[:])
	if err != nil {
		return nil, fmt.Errorf("could not get secret entry: %w", err)
	}

	if secretEntry == nil {
		return nil, errors.New("secret not found")
	}

	messageOp := msg[:8]
	if !bytes.Equal(messageOp, []byte("retrieve")) {
		return nil, errors.New("invalid message op")
	}

	messageSecretID := msg[8:40]
	if !bytes.Equal(messageSecretID, secretID) {
		return nil, errors.New("invalid secret ID in message")
	}

	messageChallenge := msg[40:56]
	messageChallengeHash := sha256.Sum256(messageChallenge)
	if subtle.ConstantTimeCompare(messageChallengeHash[:], secretEntry.ChallengeHash) != 1 {
		return nil, errors.New("invalid challenge value")
	}

	messageTimestampStr := string(msg[56:])
	timestamp, err := time.Parse(time.RFC3339, messageTimestampStr)
	if err != nil {
		return nil, errors.New("invalid timestamp in message")
	}

	secs30Ago := time.Now().Add(time.Second * (-30))
	secs30Ahead := time.Now().Add(time.Second * 30)
	if timestamp.Before(secs30Ago) || timestamp.After(secs30Ahead) {
		return nil, errors.New("invalid timestamp")
	}

	ok := ed25519.Verify(secretEntry.ReceiverPubKey, msg, sig)
	if !ok {
		return nil, errors.New("invalid signature")
	}

	if secretEntry.Expiration.Before(time.Now()) {
		return nil, errors.New("secret expired")
	}

	if err := v.kvs.Delete(secretIDHash[:]); err != nil {
		return nil, errors.New("secret could not be deleted")
	}

	return secretEntry.EncryptedSecret, nil
}

type SecretEntry struct {
	Expiration      time.Time
	ChallengeHash   []byte
	EncryptedSecret []byte
	ReceiverPubKey  []byte
}
