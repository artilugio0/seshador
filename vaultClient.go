package seshador

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type VaultClient interface {
	RetrieveSecret(secretID, msg, sig []byte) ([]byte, error)

	StoreSecret(secretID, receiverSigPub, ciphertext []byte) ([]byte, error)
}

type VaultClientHTTP struct {
	baseURL    string
	httpClient *http.Client
}

func NewVaultClientHTTP(baseURL string) *VaultClientHTTP {
	return &VaultClientHTTP{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (vch *VaultClientHTTP) WithTransport(transport *http.Transport) *VaultClientHTTP {
	vch.httpClient.Transport = transport
	return vch
}

func (vch *VaultClientHTTP) RetrieveSecret(secretID, msg, sig []byte) ([]byte, error) {
	secretURL, err := url.Parse(vch.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid vault base URL: %w", err)
	}

	secretIDStr := base64.URLEncoding.EncodeToString(secretID)
	secretURL = secretURL.JoinPath("secrets", secretIDStr)

	msgStr := base64.URLEncoding.EncodeToString(msg)
	sigStr := base64.URLEncoding.EncodeToString(sig)

	qVals := secretURL.Query()
	qVals.Add("msg", msgStr)
	qVals.Add("sig", sigStr)

	secretURLStr := secretURL.String() + "?" + qVals.Encode()
	req, err := http.NewRequest("GET", secretURLStr, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create retrieve secret request: %v", err)
	}

	res, err := vch.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secret retrieval request failed: %w", err)
	}
	defer res.Body.Close()

	vaultResp := RetrieveSecretResponse{}
	if err := json.NewDecoder(res.Body).Decode(&vaultResp); err != nil {
		return nil, fmt.Errorf("could not read vault response: %w", err)
	}

	encryptedSecret, err := base64.URLEncoding.DecodeString(vaultResp.EncryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("could not decode encrypted secret: %v", err)
	}

	return encryptedSecret, nil
}

func (vch *VaultClientHTTP) StoreSecret(secretID, receiverSigPub, encryptedSecret []byte) ([]byte, error) {
	secretURL, err := url.Parse(vch.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid vault base URL: %w", err)
	}
	secretURL = secretURL.JoinPath("secrets")

	reqBody := StoreSecretRequest{
		SecretID:          base64.URLEncoding.EncodeToString(secretID),
		ReceiverPublicKey: base64.URLEncoding.EncodeToString(receiverSigPub),
		EncryptedSecret:   base64.URLEncoding.EncodeToString(encryptedSecret),
	}

	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("could not marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", secretURL.String(), bytes.NewReader(reqBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("could not create store secret request: %v", err)
	}

	resp, err := vch.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("store secret request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody := StoreSecretResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("could not read vault response: %w", err)
	}

	challenge, err := base64.URLEncoding.DecodeString(respBody.Challenge)
	if err != nil {
		return nil, fmt.Errorf("could not decode vault challenge value: %v", err)
	}

	return challenge, nil
}
