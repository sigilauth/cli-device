package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/pictogram"
	"github.com/sigilauth/cli-device/internal/state"
)

type pairInitResponse struct {
	ServerID                  string   `json:"server_id"`
	ServerPublicKey           string   `json:"server_public_key"`
	ServerNonce               string   `json:"server_nonce"`
	ExpiresAt                 string   `json:"expires_at"`
	SessionPictogram          []string `json:"session_pictogram"`
	SessionPictogramSpeakable string   `json:"session_pictogram_speakable"`
}

type pairCompleteRequest struct {
	ServerNonce      string                 `json:"server_nonce"`
	ClientPublicKey  string                 `json:"client_public_key"`
	DeviceInfo       map[string]interface{} `json:"device_info"`
}

type pairCompleteResponse struct {
	Status          string `json:"status"`
	ServerPublicKey string `json:"server_public_key"`
	PairedAt        string `json:"paired_at"`
}

func runPair(mgr *state.Manager, serverURL string) error {
	if !mgr.Exists() {
		return fmt.Errorf("device not initialized. Run 'sigil-device init' first")
	}

	if err := validateServerURL(serverURL); err != nil {
		return err
	}

	st, err := mgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Decompress device public key for pair handshake
	devicePubKeyBytes, err := hex.DecodeString(st.DevicePublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode device public key: %w", err)
	}

	devicePubKey, err := crypto.DecompressPublicKey(devicePubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to decompress device public key: %w", err)
	}

	compressedPubKey := crypto.CompressPublicKey(devicePubKey)
	clientPubB64 := base64.StdEncoding.EncodeToString(compressedPubKey)

	// Step 1: GET /pair/init?client_pub=<base64>
	initURL := fmt.Sprintf("%s/pair/init?client_pub=%s", serverURL, url.QueryEscape(clientPubB64))
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(initURL)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var initResp pairInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return fmt.Errorf("failed to parse server response: %w", err)
	}

	// Validate response fields
	if initResp.ServerPublicKey == "" {
		return fmt.Errorf("server response missing server_public_key")
	}
	if initResp.ServerNonce == "" {
		return fmt.Errorf("server response missing server_nonce")
	}

	// Decode server public key
	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(initResp.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid server public key format: %w", err)
	}

	if len(serverPubKeyBytes) != 33 {
		return fmt.Errorf("server public key must be 33 bytes, got %d", len(serverPubKeyBytes))
	}

	serverPubKey, err := crypto.DecompressPublicKey(serverPubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}

	// Decode server nonce
	serverNonceBytes, err := base64.StdEncoding.DecodeString(initResp.ServerNonce)
	if err != nil {
		return fmt.Errorf("invalid server nonce format: %w", err)
	}

	if len(serverNonceBytes) != 32 {
		return fmt.Errorf("server nonce must be 32 bytes, got %d", len(serverNonceBytes))
	}

	// Step 2: Derive session pictogram locally (Argon2id per spec §4.2)
	emojis, words, err := pictogram.DeriveSessionPictogram(serverPubKeyBytes, compressedPubKey, serverNonceBytes)
	if err != nil {
		return fmt.Errorf("failed to derive session pictogram: %w", err)
	}

	// Step 3: Display session pictogram and MANDATORY user confirmation
	fmt.Printf("\n═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  PAIR HANDSHAKE — SESSION PICTOGRAM VERIFICATION\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")
	fmt.Printf("Session pictogram:\n\n")
	fmt.Printf("  %s\n\n", pictogram.FormatSessionPictogram(emojis, words))
	fmt.Printf("Speakable: %s\n\n", pictogram.SpeakableSessionPictogram(words))
	fmt.Printf("Server claims: %s\n\n", initResp.SessionPictogramSpeakable)
	fmt.Printf("Expires at: %s\n\n", initResp.ExpiresAt)

	// Verify server's pictogram matches our derivation
	serverSpeakable := pictogram.SpeakableSessionPictogram(words)
	if initResp.SessionPictogramSpeakable != serverSpeakable {
		fmt.Printf("❌ PICTOGRAM MISMATCH — POSSIBLE MITM ATTACK\n\n")
		fmt.Printf("Expected: %s\n", serverSpeakable)
		fmt.Printf("Server sent: %s\n\n", initResp.SessionPictogramSpeakable)
		return fmt.Errorf("session pictogram mismatch — MITM attack detected")
	}

	fmt.Printf("✓ Session pictogram matches local derivation\n\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  SECURITY CHECKPOINT\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")
	fmt.Printf("Verify this pictogram with your administrator via voice, chat,\n")
	fmt.Printf("or other out-of-band channel. The pictogram expires in 10 seconds.\n\n")
	fmt.Printf("Do you confirm the pictogram matches? (yes/no): ")

	// MANDATORY user prompt (no auto-confirm flag per spec requirement)
	reader := bufio.NewReader(os.Stdin)
	confirmation, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	confirmation = strings.TrimSpace(strings.ToLower(confirmation))
	if confirmation != "yes" && confirmation != "y" {
		fmt.Printf("\n❌ Pair handshake cancelled by user\n\n")
		return fmt.Errorf("user rejected session pictogram")
	}

	fmt.Printf("\n✓ User confirmed session pictogram\n\n")

	// Step 4: POST /pair/complete
	completeURL := serverURL + "/pair/complete"

	completeReq := pairCompleteRequest{
		ServerNonce:     initResp.ServerNonce,
		ClientPublicKey: clientPubB64,
		DeviceInfo: map[string]interface{}{
			"name":       "CLI Device",
			"platform":   "cli",
			"os_version": "unknown",
		},
	}

	reqJSON, err := json.Marshal(completeReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	completeResp, err := client.Post(completeURL, "application/json", strings.NewReader(string(reqJSON)))
	if err != nil {
		return fmt.Errorf("failed to complete pair: %w", err)
	}
	defer completeResp.Body.Close()

	if completeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(completeResp.Body)
		return fmt.Errorf("server returned %d: %s", completeResp.StatusCode, string(body))
	}

	var completeResult pairCompleteResponse
	if err := json.NewDecoder(completeResp.Body).Decode(&completeResult); err != nil {
		return fmt.Errorf("failed to parse pair complete response: %w", err)
	}

	if completeResult.Status != "paired" {
		return fmt.Errorf("unexpected status: %s", completeResult.Status)
	}

	// Update state
	st.ServerPublicKey = initResp.ServerPublicKey
	st.ServerURL = serverURL

	if err := mgr.Save(st); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	// Display success
	serverFingerprint := state.FingerprintFromPublicKey(serverPubKey)

	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  ✓ PAIRED SUCCESSFULLY\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")
	fmt.Printf("Server URL: %s\n", serverURL)
	fmt.Printf("Server fingerprint: %s\n", serverFingerprint)
	fmt.Printf("Paired at: %s\n\n", completeResult.PairedAt)

	return nil
}

func validateServerURL(serverURL string) error {
	if serverURL == "" {
		return fmt.Errorf("server URL is required")
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("server URL must use http:// or https://")
	}

	if u.Host == "" {
		return fmt.Errorf("server URL must include host")
	}

	return nil
}

func cmdPair(args []string) error {
	serverURL := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--server" || args[i] == "-s" {
			if i+1 >= len(args) {
				return fmt.Errorf("--server flag requires a URL argument")
			}
			serverURL = args[i+1]
			i++
		}
	}

	if serverURL == "" {
		return fmt.Errorf("--server flag is required. Usage: sigil-device pair --server <url>")
	}

	mgr := state.DefaultManager()
	return runPair(mgr, serverURL)
}
