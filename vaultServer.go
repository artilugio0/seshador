package seshador

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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
	vs.mux.HandleFunc("GET /secrets/{secretID}", handlerSecretRetrieve(vault))
	vs.mux.HandleFunc("POST /secrets", handlerSecretStore(vault))
}

func handlerSecretRetrieve(vault *Vault) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		secretIDStr := req.PathValue("secretID")
		secretID, err := base64.StdEncoding.DecodeString(secretIDStr)
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

		msg, err := base64.StdEncoding.DecodeString(msgList[0])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sigList := values["sig"]
		if len(sigList) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sig, err := base64.StdEncoding.DecodeString(sigList[0])
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
			EncryptedSecret: base64.StdEncoding.EncodeToString(secret),
		}

		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func handlerSecretStore(vault *Vault) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()

		input := StoreSecretRequest{}
		if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// TODO: validate min max lengths
		if input.SecretID == "" || input.EncryptedSecret == "" || input.ReceiverPublicKey == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		secretID, err := base64.StdEncoding.DecodeString(input.SecretID)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		encryptedSecret, err := base64.StdEncoding.DecodeString(input.EncryptedSecret)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receiverPublicKey, err := base64.StdEncoding.DecodeString(input.ReceiverPublicKey)
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
			Challenge: base64.StdEncoding.EncodeToString(challenge),
		}

		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
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
