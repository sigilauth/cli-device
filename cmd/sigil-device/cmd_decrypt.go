package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/envelope"
	"github.com/sigilauth/cli-device/internal/state"
)

type DecryptRequestInput struct {
	DecryptID       string `json:"decrypt_id"`
	Ciphertext      string `json:"ciphertext"`
	ServerSignature string `json:"server_signature"`
	ExpiresAt       string `json:"expires_at"`
}

func cmdDecryptWrapper(args []string) error {
	mgr := state.DefaultManager()

	var decryptFile string
	var serverURL string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--decrypt-file", "-f":
			if i+1 >= len(args) {
				return fmt.Errorf("--decrypt-file requires a path")
			}
			decryptFile = args[i+1]
			i++
		case "--server", "-s":
			if i+1 >= len(args) {
				return fmt.Errorf("--server requires a URL")
			}
			serverURL = args[i+1]
			i++
		}
	}

	privKey, err := loadPrivateKey(mgr)
	if err != nil {
		return err
	}

	return runDecrypt(mgr, privKey, decryptFile, "", serverURL)
}

func runDecrypt(mgr *state.Manager, devicePrivKey *ecdsa.PrivateKey, decryptFile string, stdinOverride string, serverURL string) error {
	if !mgr.Exists() {
		return fmt.Errorf("device not initialized. Run 'sigil-device init' first")
	}

	st, err := mgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	if st.ServerPublicKey == "" {
		return fmt.Errorf("device not paired with any server. Run 'sigil-device pair' first")
	}

	if serverURL == "" {
		serverURL = st.ServerURL
	}

	// Read decrypt request
	var decryptJSON []byte
	if decryptFile != "" {
		decryptJSON, err = os.ReadFile(decryptFile)
		if err != nil {
			return fmt.Errorf("failed to read decrypt file: %w", err)
		}
	} else if stdinOverride != "" {
		decryptJSON, err = os.ReadFile(stdinOverride)
		if err != nil {
			return fmt.Errorf("failed to read stdin override: %w", err)
		}
	} else {
		decryptJSON, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
	}

	var decryptReq DecryptRequestInput
	if err := json.Unmarshal(decryptJSON, &decryptReq); err != nil {
		return fmt.Errorf("failed to parse decrypt JSON: %w", err)
	}

	if decryptReq.DecryptID == "" || decryptReq.Ciphertext == "" || decryptReq.ServerSignature == "" {
		return fmt.Errorf("decrypt request missing required fields")
	}

	// Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(decryptReq.Ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Decode server signature
	serverSigBytes, err := base64.StdEncoding.DecodeString(decryptReq.ServerSignature)
	if err != nil {
		return fmt.Errorf("failed to decode server signature: %w", err)
	}

	// Decode server public key from state
	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(st.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode server public key: %w", err)
	}

	serverPubKey, err := crypto.DecompressPublicKey(serverPubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to decompress server public key: %w", err)
	}

	// Verify server signature on envelope (decrypt_id + ciphertext)
	envelopeBytes := []byte(decryptReq.DecryptID + decryptReq.Ciphertext)
	if err := crypto.Verify(serverPubKey, envelopeBytes, serverSigBytes); err != nil {
		return fmt.Errorf("server signature verification failed: %w", err)
	}

	fmt.Println("✓ Server signature verified")

	// ECIES decrypt (salt = decrypt_id)
	salt := []byte(decryptReq.DecryptID)
	plaintext, err := crypto.Decrypt(devicePrivKey, ciphertext, salt)
	if err != nil {
		return fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	fmt.Printf("✓ Decrypted %d bytes\n", len(plaintext))

	// Build request body for envelope
	nonce, err := envelope.GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	body := map[string]interface{}{
		"decrypt_id": decryptReq.DecryptID,
		"plaintext":  base64.StdEncoding.EncodeToString(plaintext),
	}

	// Create envelope
	envelopeB64, err := envelope.CreateRequest(devicePrivKey, serverPubKey, "decrypt.respond", body, nonce)
	if err != nil {
		return fmt.Errorf("failed to create envelope: %w", err)
	}

	// POST to /envelope endpoint
	envelopeURL := serverURL + "/envelope"
	reqBody := map[string]string{
		"envelope": envelopeB64,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(envelopeURL, "application/json", bytes.NewReader(reqJSON))
	if err != nil {
		return fmt.Errorf("failed to POST envelope: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var respEnvelope map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&respEnvelope); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Verify response envelope
	nonceStore := make(map[string]bool)
	payload, err := envelope.VerifyResponse(devicePrivKey, serverPubKey, respEnvelope["envelope"], nonceStore)
	if err != nil {
		return fmt.Errorf("failed to verify response envelope: %w", err)
	}

	fmt.Printf("✓ Response envelope verified\n")
	fmt.Printf("✓ Plaintext submitted successfully\n")
	fmt.Printf("Status: %s\n", payload.Status)

	return nil
}
