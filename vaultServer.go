package seshador

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
)

const (
	maxLengthStoreSecretInputSize int = (secretIDSize+publicKeySize+maxEncryptedSecretSize)*4/3 + 100 // +100 to account for json and rounding errors
	maxEncryptedSecretSize        int = encryptionNonceSize + 4096 + 16                               // nonce + plaintext + tag
	maxRetrieveMessageSize        int = 80
	maxRetrieveSignatureSize      int = 64
)

type VaultServer struct {
	mux *http.ServeMux
}

func NewVaultServer(vault *Vault) *VaultServer {
	server := &VaultServer{
		mux: http.NewServeMux(),
	}

	server.configureHandlers(vault)

	return server
}

func (vs *VaultServer) configureHandlers(vault *Vault) {
	vs.mux.HandleFunc("GET /ping", handlerPing())

	vs.mux.HandleFunc("GET /secrets/{secretID}", handlerSecretRetrieve(vault))
	vs.mux.HandleFunc("POST /secrets", handlerSecretStore(vault))
}

func handlerSecretRetrieve(vault *Vault) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		secretIDStr := req.PathValue("secretID")
		if len(secretIDStr) > base64.URLEncoding.EncodedLen(secretIDSize) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		secretID, err := base64.URLEncoding.DecodeString(secretIDStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		values := req.URL.Query()
		msgList := values["msg"]
		if len(msgList) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		msgStr := msgList[0]

		if len(msgStr) > base64.URLEncoding.EncodedLen(maxRetrieveMessageSize) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		msg, err := base64.URLEncoding.DecodeString(msgList[0])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sigList := values["sig"]
		if len(sigList) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sigStr := sigList[0]

		if len(sigStr) > base64.URLEncoding.EncodedLen(maxRetrieveSignatureSize) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sig, err := base64.URLEncoding.DecodeString(sigList[0])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		secret, err := vault.RetrieveSecret(secretID, msg, sig)
		if err != nil {
			// TODO: distinguish different errors
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response := RetrieveSecretResponse{
			EncryptedSecret: base64.URLEncoding.EncodeToString(secret),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			return
		}
	}
}

func handlerSecretStore(vault *Vault) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()

		limitReader := io.LimitReader(req.Body, int64(maxLengthStoreSecretInputSize))

		input := StoreSecretRequest{}
		if err := json.NewDecoder(limitReader).Decode(&input); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if len(input.SecretID) != base64.URLEncoding.EncodedLen(secretIDSize) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if len(input.EncryptedSecret) < base64.URLEncoding.EncodedLen(encryptionNonceSize+16) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if len(input.ReceiverPublicKey) != base64.URLEncoding.EncodedLen(ed25519.PublicKeySize) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		secretID, err := base64.URLEncoding.DecodeString(input.SecretID)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		encryptedSecret, err := base64.URLEncoding.DecodeString(input.EncryptedSecret)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receiverPublicKey, err := base64.URLEncoding.DecodeString(input.ReceiverPublicKey)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		challenge, err := vault.StoreSecret(secretID, receiverPublicKey, encryptedSecret)
		if err != nil {
			// TODO: distinguish different errors
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response := StoreSecretResponse{
			Challenge: base64.URLEncoding.EncodeToString(challenge),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			return
		}
	}
}

func handlerPing() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func (vs *VaultServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	vs.mux.ServeHTTP(w, req)
}

type RetrieveSecretResponse struct {
	EncryptedSecret string `json:"encrypted_secret"`
}

type StoreSecretRequest struct {
	SecretID          string `json:"secret_id"`
	EncryptedSecret   string `json:"encrypted_secret"`
	ReceiverPublicKey string `json:"receiver_public_key"`
}

type StoreSecretResponse struct {
	Challenge string `json:"challenge"`
}
