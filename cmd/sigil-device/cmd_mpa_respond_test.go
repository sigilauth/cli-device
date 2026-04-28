package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/state"
)

func TestCmdMPARespond(t *testing.T) {
	// Generate server and device keypairs
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverPubKeyCompressed := crypto.CompressPublicKey(&serverKey.PublicKey)
	serverPubKeyB64 := base64.StdEncoding.EncodeToString(serverPubKeyCompressed)

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devicePubKeyCompressed := crypto.CompressPublicKey(&deviceKey.PublicKey)
	devicePubKeyHex := fmt.Sprintf("%x", devicePubKeyCompressed)

	fingerprint := sha256.Sum256(devicePubKeyCompressed)
	fingerprintHex := fmt.Sprintf("%x", fingerprint[:])

	t.Run("responds to valid MPA request from file", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol (POST /envelope)")

		// Create mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/mpa/respond" {
				http.Error(w, "not found", 404)
				return
			}

			var req map[string]string
			json.NewDecoder(r.Body).Decode(&req)

			if req["request_id"] == "" || req["fingerprint"] == "" || req["signature"] == "" {
				http.Error(w, "missing fields", 400)
				return
			}

			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "approved",
			})
		}))
		defer server.Close()

		// Create test state
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          server.URL,
			ServerPublicKey:    serverPubKeyB64,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)

		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		mgr.SaveMnemonic(mnemonic)

		// Create action context and encrypt with device public key
		actionContext := map[string]interface{}{
			"type":        "transfer",
			"description": "Transfer $1000 to Alice",
			"params": map[string]interface{}{
				"amount":    "1000.00",
				"recipient": "alice@example.com",
			},
		}
		actionContextJSON, _ := json.Marshal(actionContext)

		requestID := "mpa-request-123"
		salt := []byte(requestID)

		// Encrypt action context with device public key
		encryptedActionContext, err := crypto.Encrypt(&deviceKey.PublicKey, actionContextJSON, salt)
		if err != nil {
			t.Fatalf("Failed to encrypt action context: %v", err)
		}

		// Server signs the request envelope
		envelopeBytes := []byte(requestID + base64.StdEncoding.EncodeToString(encryptedActionContext))
		serverSig, _ := crypto.Sign(serverKey, envelopeBytes)

		mpaRequest := map[string]string{
			"request_id":       requestID,
			"action_context":   base64.StdEncoding.EncodeToString(encryptedActionContext),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		mpaFile := filepath.Join(tmpDir, "mpa.json")
		mpaJSON, _ := json.Marshal(mpaRequest)
		os.WriteFile(mpaFile, mpaJSON, 0600)

		// Run mpa-respond with auto-approve
		err = runMPARespond(mgr, deviceKey, mpaFile, "", server.URL, true)
		if err != nil {
			t.Errorf("runMPARespond failed: %v", err)
		}
	})

	t.Run("rejects MPA with invalid server signature", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://example.com",
			ServerPublicKey:    serverPubKeyB64,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		// Create MPA with invalid signature
		wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		actionContextJSON := []byte(`{"type":"transfer","description":"Transfer $1000"}`)
		encryptedActionContext, _ := crypto.Encrypt(&deviceKey.PublicKey, actionContextJSON, []byte("test-req"))

		wrongSig, _ := crypto.Sign(wrongKey, []byte("test-req"+base64.StdEncoding.EncodeToString(encryptedActionContext)))

		mpaRequest := map[string]string{
			"request_id":       "test-req",
			"action_context":   base64.StdEncoding.EncodeToString(encryptedActionContext),
			"server_signature": base64.StdEncoding.EncodeToString(wrongSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		mpaFile := filepath.Join(tmpDir, "bad-mpa.json")
		mpaJSON, _ := json.Marshal(mpaRequest)
		os.WriteFile(mpaFile, mpaJSON, 0600)

		err := runMPARespond(mgr, deviceKey, mpaFile, "", "http://example.com", true)
		if err == nil {
			t.Error("Expected error for invalid server signature")
		}
		if !strings.Contains(err.Error(), "signature") {
			t.Errorf("Expected signature error, got: %v", err)
		}
	})

	t.Run("fails when not paired", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)

		err := runMPARespond(mgr, deviceKey, "", "", "http://example.com", true)
		if err == nil {
			t.Error("Expected error when not paired")
		}
		if !strings.Contains(err.Error(), "not paired") {
			t.Errorf("Expected 'not paired' error, got: %v", err)
		}
	})
}
