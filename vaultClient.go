package seshador

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type VaultClient interface {
	RetrieveSecret(secretID, msg, sig []byte) ([]byte, error)

	StoreSecret(secretID, receiverSigPub, ciphertext []byte) ([]byte, error)
}

type VaultClientHTTP struct {
	BaseURL string
}

func (vch *VaultClientHTTP) RetrieveSecret(secretID, msg, sig []byte) ([]byte, error) {
	secretURL, err := url.Parse(vch.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid vault base URL: %w", err)
	}

	secretIDStr := base64.StdEncoding.EncodeToString(secretID)
	secretURL = secretURL.JoinPath("secrets", url.PathEscape(secretIDStr))

	msgStr := base64.StdEncoding.EncodeToString(msg)
	sigStr := base64.StdEncoding.EncodeToString(sig)

	qVals := secretURL.Query()
	qVals.Add("msg", msgStr)
	qVals.Add("sig", sigStr)

	secretURLStr := secretURL.String() + "?" + qVals.Encode()
	res, err := http.Get(secretURLStr)
	if err != nil {
		return nil, fmt.Errorf("secret retrieval request failed: %w", err)
	}
	defer res.Body.Close()

	vaultResp := VaultResponse{}
	if err := json.NewDecoder(res.Body).Decode(&vaultResp); err != nil {
		return nil, fmt.Errorf("could not read vault response: %w", err)
	}

	return vaultResp.EncryptedSecret, nil
}

type VaultResponse struct {
	EncryptedSecret []byte
}
