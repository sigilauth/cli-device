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

type ChallengeInput struct {
	ChallengeID     string                 `json:"challenge_id"`
	Challenge       string                 `json:"challenge"`
	ServerSignature string                 `json:"server_signature"`
	ExpiresAt       string                 `json:"expires_at"`
	ActionContext   map[string]interface{} `json:"action_context,omitempty"`
}

func cmdRespondWrapper(args []string) error {
	mgr := state.DefaultManager()

	var challengeFile string
	var serverURL string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--challenge-file", "-f":
			if i+1 >= len(args) {
				return fmt.Errorf("--challenge-file requires a path")
			}
			challengeFile = args[i+1]
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

	return runRespond(mgr, privKey, challengeFile, "", serverURL)
}

func runRespond(mgr *state.Manager, devicePrivKey *ecdsa.PrivateKey, challengeFile string, stdinOverride string, serverURL string) error {
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

	// Read challenge input
	var challengeJSON []byte
	if challengeFile != "" {
		challengeJSON, err = os.ReadFile(challengeFile)
		if err != nil {
			return fmt.Errorf("failed to read challenge file: %w", err)
		}
	} else if stdinOverride != "" {
		challengeJSON, err = os.ReadFile(stdinOverride)
		if err != nil {
			return fmt.Errorf("failed to read stdin override: %w", err)
		}
	} else {
		challengeJSON, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
	}

	var challenge ChallengeInput
	if err := json.Unmarshal(challengeJSON, &challenge); err != nil {
		return fmt.Errorf("failed to parse challenge JSON: %w", err)
	}

	if challenge.ChallengeID == "" || challenge.Challenge == "" || challenge.ServerSignature == "" {
		return fmt.Errorf("challenge missing required fields (challenge_id, challenge, server_signature)")
	}

	// Decode challenge bytes
	challengeBytes, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}

	// Decode server signature
	serverSigBytes, err := base64.StdEncoding.DecodeString(challenge.ServerSignature)
	if err != nil {
		return fmt.Errorf("failed to decode server signature: %w", err)
	}

	if len(serverSigBytes) != 64 {
		return fmt.Errorf("server signature must be 64 bytes, got %d", len(serverSigBytes))
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

	// Compute action context hash (V1 spec)
	var actionCtx interface{}
	if challenge.ActionContext != nil {
		actionCtx = challenge.ActionContext
	}
	actionHash, err := crypto.ComputeActionContextHash(actionCtx)
	if err != nil {
		return fmt.Errorf("failed to compute action context hash: %w", err)
	}

	// Build signed message: challenge_bytes || action_hash
	message := append(challengeBytes, actionHash...)

	// Verify server signature (domain-separated with SIGIL-AUTH-V1)
	taggedMessage := append(crypto.DomainAuth, message...)
	if err := crypto.Verify(serverPubKey, taggedMessage, serverSigBytes); err != nil {
		return fmt.Errorf("server signature verification failed: %w", err)
	}

	fmt.Println("✓ Server signature verified")

	// Sign challenge with device key (domain-separated with SIGIL-AUTH-V1)
	deviceSig, err := crypto.SignWithDomain(devicePrivKey, crypto.DomainAuth, message)
	if err != nil {
		return fmt.Errorf("failed to sign challenge: %w", err)
	}

	// Build request body for envelope
	nonce, err := envelope.GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	body := map[string]interface{}{
		"challenge_id": challenge.ChallengeID,
		"signature":    base64.StdEncoding.EncodeToString(deviceSig),
	}

	// Create envelope
	envelopeB64, err := envelope.CreateRequest(devicePrivKey, serverPubKey, "challenge.respond", body, nonce)
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
	fmt.Printf("Status: %s\n", payload.Status)

	if payload.Body != nil {
		if msg, ok := payload.Body["message"].(string); ok {
			fmt.Printf("Message: %s\n", msg)
		}
	}

	return nil
}
