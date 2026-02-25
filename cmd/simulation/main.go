package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

const hkdfUrlInfo = "seshador/v1/hkdf/info/url"
const hkdfEncryptionKeyInfo = "seshador/v1/hkdf/info/encryption-key"

func main() {
	secret := "this is a secret string"

	senderReceiverChan := make(chan []byte)
	senderServerChan := make(chan []byte)
	receiverServerChan := make(chan []byte)

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		receiver(senderReceiverChan, receiverServerChan)
	}()

	go func() {
		defer wg.Done()
		sender(secret, senderReceiverChan, senderServerChan)
	}()

	go func() {
		defer wg.Done()
		server(senderServerChan, receiverServerChan)
	}()

	wg.Wait()
}

func receiver(sender chan []byte, server chan []byte) {
	// Receiver creates 2 keys signs and sends values
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	curve := ecdh.X25519()
	recPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	recPub := recPriv.PublicKey()

	message1 := slices.Concat(recPub.Bytes(), sigPub)
	fmt.Println("[Receiver] sending to sender:", base64.StdEncoding.EncodeToString(message1))
	sender <- message1

	// Receive sender public key and server challenge
	message2 := <-sender
	senderPubBytes := message2[:32]
	serverChallenge := message2[32:48]

	senderPub, err := curve.NewPublicKey(senderPubBytes)
	if err != nil {
		panic(err)
	}

	sharedSecret, err := recPriv.ECDH(senderPub)
	if err != nil {
		panic(err)
	}
	fmt.Println("[Receiver] computed shared secret:", hex.EncodeToString(sharedSecret))

	urlKey, err := hkdf.Key(sha256.New, sharedSecret, nil, hkdfUrlInfo, 32)
	if err != nil {
		panic(err)
	}

	// Ask server for encrypted secret
	fmt.Println("[Receiver] sending request to server to get encrypted secret: URL key:", base64.StdEncoding.EncodeToString(urlKey))
	timestamp := time.Now().Format(time.RFC3339)
	message3 := slices.Concat([]byte("retrieve"), urlKey, serverChallenge, []byte(timestamp))
	sig1 := ed25519.Sign(sigPriv, message3)

	server <- urlKey
	server <- message3
	server <- sig1

	// Decrypt the ciphertext
	ciphertext := <-server

	// Strip nonce from ciphertext
	encNonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	// Generate encryption key
	encKey, err := hkdf.Key(sha256.New, sharedSecret, nil, hkdfEncryptionKeyInfo, 32)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"[Receiver] decrypting secret with encryption key '%s' and nonce '%s'\n",
		hex.EncodeToString(encKey),
		hex.EncodeToString(encNonce),
	)

	plaintext, err := aesGcm.Open(nil, encNonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	recoveredSecret := string(plaintext)
	fmt.Println("[Receiver] recovered secret:", recoveredSecret)
}

func sender(secret string, receiver chan []byte, server chan []byte) {
	message1 := <-receiver
	recPubBytes := message1[:32]
	recSigPubBytes := message1[32:64]

	curve := ecdh.X25519()
	recPub, err := curve.NewPublicKey(recPubBytes)
	if err != nil {
		panic(err)
	}

	sendPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	sendPub := sendPriv.PublicKey()

	sharedSecret, err := sendPriv.ECDH(recPub)
	if err != nil {
		panic(err)
	}
	fmt.Println("[Sender] computed shared secret:", hex.EncodeToString(sharedSecret))

	urlKey, err := hkdf.Key(sha256.New, sharedSecret, nil, hkdfUrlInfo, 32)
	if err != nil {
		panic(err)
	}

	encKey, err := hkdf.Key(sha256.New, sharedSecret, nil, hkdfEncryptionKeyInfo, 32)
	if err != nil {
		panic(err)
	}

	encNonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, encNonce); err != nil {
		panic(err)
	}

	fmt.Printf(
		"[Sender] encrypting secret with encryption key '%s' and nonce '%s'\n",
		hex.EncodeToString(encKey),
		hex.EncodeToString(encNonce),
	)

	aesBlock, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err)
	}
	aesGcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		panic(err)
	}

	ciphertext := aesGcm.Seal(nil, encNonce, []byte(secret), nil)
	// Prepend nonce to ciphertext
	ciphertext = slices.Concat(encNonce, ciphertext)

	fmt.Println("[Sender] sending encrypted secret to server. URL key:", base64.StdEncoding.EncodeToString(urlKey))
	server <- urlKey
	server <- recSigPubBytes
	server <- ciphertext

	challenge := <-server

	message := slices.Concat(sendPub.Bytes(), challenge)
	fmt.Println("[Sender] sending public key and challenge to receiver:", base64.StdEncoding.EncodeToString(message))
	receiver <- message
}

func server(sender chan []byte, receiver chan []byte) {
	urlKey := <-sender
	recSigPubBytes := <-sender
	ciphertext := <-sender

	expiration := time.Now().Add(24 * time.Hour)

	challenge := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		panic(err)
	}

	challengeHash := sha256.Sum256(challenge)

	fmt.Println("[Server] sending challenge to sender: ", base64.StdEncoding.EncodeToString(challenge))
	sender <- challenge

	urlKeyHash := sha256.Sum256(urlKey)
	fmt.Println("[Server] received request to store encrypted secret. URL Key hash:", hex.EncodeToString(urlKeyHash[:]))

	recUrlKey := <-receiver
	recMessage := <-receiver
	recSig := <-receiver

	recUrlKeyHash := sha256.Sum256(recUrlKey)
	fmt.Println("[Server] received request to read encrypted secret. URL Key hash:", hex.EncodeToString(recUrlKeyHash[:]))

	if !bytes.Equal(recUrlKeyHash[:], urlKeyHash[:]) {
		panic("invalid url key")
	}

	messageOp := recMessage[:8]
	if !bytes.Equal(messageOp, []byte("retrieve")) {
		panic("invalid message op")
	}

	messageUrlKey := recMessage[8:40]
	if !bytes.Equal(messageUrlKey, urlKey) {
		panic("invalid url key")
	}

	messageChallenge := recMessage[40:56]
	messageChallengeHash := sha256.Sum256(messageChallenge)
	if !bytes.Equal(messageChallengeHash[:], challengeHash[:]) {
		panic("invalid challenge value")
	}

	messageTimestampStr := string(recMessage[56:])
	timestamp, err := time.Parse(time.RFC3339, messageTimestampStr)
	if err != nil {
		panic(err)
	}

	min1Ago := time.Now().Add(time.Second * (-30))
	if timestamp.Before(min1Ago) {
		panic("invalid timestamp")
	}

	recPub := ed25519.PublicKey(recSigPubBytes)
	ok := ed25519.Verify(recPub, recMessage, recSig)
	if !ok {
		panic("invalid signature")
	}

	if expiration.Before(time.Now()) {
		panic("secret expired")
	}

	fmt.Println("[Server] request validated. Valid URL key, signature vefified and not expired")

	fmt.Println("[Server] challenge marked as used")
	challenge = nil
	receiver <- ciphertext

	fmt.Println("[Server] encrypted secret deleted") // just a message, real implementation does mark it
	ciphertext = nil
}
