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

type MPARequestInput struct {
	RequestID       string `json:"request_id"`
	ActionContext   string `json:"action_context"`
	ServerSignature string `json:"server_signature"`
	ExpiresAt       string `json:"expires_at"`
}

type ActionContext struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Params      map[string]interface{} `json:"params"`
}

func cmdMPARespondWrapper(args []string) error {
	mgr := state.DefaultManager()

	var mpaFile string
	var serverURL string
	var autoApprove bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--mpa-file", "-f":
			if i+1 >= len(args) {
				return fmt.Errorf("--mpa-file requires a path")
			}
			mpaFile = args[i+1]
			i++
		case "--server", "-s":
			if i+1 >= len(args) {
				return fmt.Errorf("--server requires a URL")
			}
			serverURL = args[i+1]
			i++
		case "--auto-approve", "-a":
			autoApprove = true
		}
	}

	privKey, err := loadPrivateKey(mgr)
	if err != nil {
		return err
	}

	return runMPARespond(mgr, privKey, mpaFile, "", serverURL, autoApprove)
}

func runMPARespond(mgr *state.Manager, devicePrivKey *ecdsa.PrivateKey, mpaFile string, stdinOverride string, serverURL string, autoApprove bool) error {
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

	// Read MPA request
	var mpaJSON []byte
	if mpaFile != "" {
		mpaJSON, err = os.ReadFile(mpaFile)
		if err != nil {
			return fmt.Errorf("failed to read MPA file: %w", err)
		}
	} else if stdinOverride != "" {
		mpaJSON, err = os.ReadFile(stdinOverride)
		if err != nil {
			return fmt.Errorf("failed to read stdin override: %w", err)
		}
	} else {
		mpaJSON, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
	}

	var mpaReq MPARequestInput
	if err := json.Unmarshal(mpaJSON, &mpaReq); err != nil {
		return fmt.Errorf("failed to parse MPA JSON: %w", err)
	}

	if mpaReq.RequestID == "" || mpaReq.ActionContext == "" || mpaReq.ServerSignature == "" {
		return fmt.Errorf("MPA request missing required fields")
	}

	// Decode encrypted action context
	encryptedActionContext, err := base64.StdEncoding.DecodeString(mpaReq.ActionContext)
	if err != nil {
		return fmt.Errorf("failed to decode action context: %w", err)
	}

	// Decode server signature
	serverSigBytes, err := base64.StdEncoding.DecodeString(mpaReq.ServerSignature)
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

	// Verify server signature on envelope (request_id + encrypted_action_context)
	envelopeBytes := []byte(mpaReq.RequestID + mpaReq.ActionContext)
	if err := crypto.Verify(serverPubKey, envelopeBytes, serverSigBytes); err != nil {
		return fmt.Errorf("server signature verification failed: %w", err)
	}

	fmt.Println("✓ Server signature verified")

	// ECIES decrypt action context (salt = request_id)
	salt := []byte(mpaReq.RequestID)
	actionContextJSON, err := crypto.Decrypt(devicePrivKey, encryptedActionContext, salt)
	if err != nil {
		return fmt.Errorf("failed to decrypt action context: %w", err)
	}

	// Parse action context
	var actionCtx ActionContext
	if err := json.Unmarshal(actionContextJSON, &actionCtx); err != nil {
		return fmt.Errorf("failed to parse action context: %w", err)
	}

	// Display action details
	fmt.Println("\n=== Multi-Party Authorization Request ===")
	fmt.Printf("Request ID: %s\n", mpaReq.RequestID)
	fmt.Printf("Action Type: %s\n", actionCtx.Type)
	fmt.Printf("Description: %s\n", actionCtx.Description)
	if len(actionCtx.Params) > 0 {
		fmt.Println("\nParameters:")
		for k, v := range actionCtx.Params {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
	fmt.Println()

	// Get approval
	if !autoApprove {
		fmt.Print("Approve this action? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Action rejected")
			return nil
		}
	}

	// Sign the action context bytes with MPA domain tag
	deviceSig, err := crypto.SignWithDomain(devicePrivKey, crypto.DomainMPA, actionContextJSON)
	if err != nil {
		return fmt.Errorf("failed to sign action context: %w", err)
	}

	// Build request body for envelope
	nonce, err := envelope.GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	body := map[string]interface{}{
		"request_id":  mpaReq.RequestID,
		"fingerprint": st.Fingerprint,
		"signature":   base64.StdEncoding.EncodeToString(deviceSig),
	}

	// Create envelope
	envelopeB64, err := envelope.CreateRequest(devicePrivKey, serverPubKey, "mpa.respond", body, nonce)
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
	fmt.Printf("✓ MPA approval submitted successfully\n")
	fmt.Printf("Status: %s\n", payload.Status)

	return nil
}
