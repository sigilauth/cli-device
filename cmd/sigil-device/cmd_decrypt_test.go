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

func TestCmdDecrypt(t *testing.T) {
	// Generate server and device keypairs
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverPubKeyCompressed := crypto.CompressPublicKey(&serverKey.PublicKey)
	serverPubKeyB64 := base64.StdEncoding.EncodeToString(serverPubKeyCompressed)

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devicePubKeyCompressed := crypto.CompressPublicKey(&deviceKey.PublicKey)
	devicePubKeyHex := fmt.Sprintf("%x", devicePubKeyCompressed)

	fingerprint := sha256.Sum256(devicePubKeyCompressed)
	fingerprintHex := fmt.Sprintf("%x", fingerprint[:])

	t.Run("decrypts and responds to valid decrypt request", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol (POST /envelope)")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/v1/secure/decrypt/respond" {
				http.Error(w, "not found", 404)
				return
			}

			var req map[string]string
			json.NewDecoder(r.Body).Decode(&req)

			if req["decrypt_id"] == "" || req["plaintext"] == "" {
				http.Error(w, "missing fields", 400)
				return
			}

			// Verify plaintext is correct
			plaintext, _ := base64.StdEncoding.DecodeString(req["plaintext"])
			if string(plaintext) != "secret message" {
				http.Error(w, "wrong plaintext", 400)
				return
			}

			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "decrypted",
			})
		}))
		defer server.Close()

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
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		// Encrypt plaintext with device public key
		decryptID := "decrypt-123"
		plaintext := []byte("secret message")
		salt := []byte(decryptID)

		ciphertext, err := crypto.Encrypt(&deviceKey.PublicKey, plaintext, salt)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Server signs the request
		envelope := []byte(decryptID + base64.StdEncoding.EncodeToString(ciphertext))
		serverSig, _ := crypto.Sign(serverKey, envelope)

		decryptReq := map[string]string{
			"decrypt_id":       decryptID,
			"ciphertext":       base64.StdEncoding.EncodeToString(ciphertext),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		decryptFile := filepath.Join(tmpDir, "decrypt.json")
		decryptJSON, _ := json.Marshal(decryptReq)
		os.WriteFile(decryptFile, decryptJSON, 0600)

		err = runDecrypt(mgr, deviceKey, decryptFile, "", server.URL)
		if err != nil {
			t.Errorf("runDecrypt failed: %v", err)
		}
	})

	t.Run("rejects decrypt request with invalid server signature", func(t *testing.T) {
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

		wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ciphertext, _ := crypto.Encrypt(&deviceKey.PublicKey, []byte("test"), []byte("test-id"))
		wrongSig, _ := crypto.Sign(wrongKey, []byte("test-id"+base64.StdEncoding.EncodeToString(ciphertext)))

		decryptReq := map[string]string{
			"decrypt_id":       "test-id",
			"ciphertext":       base64.StdEncoding.EncodeToString(ciphertext),
			"server_signature": base64.StdEncoding.EncodeToString(wrongSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		decryptFile := filepath.Join(tmpDir, "bad-decrypt.json")
		decryptJSON, _ := json.Marshal(decryptReq)
		os.WriteFile(decryptFile, decryptJSON, 0600)

		err := runDecrypt(mgr, deviceKey, decryptFile, "", "http://example.com")
		if err == nil {
			t.Error("Expected error for invalid server signature")
		}
		if !strings.Contains(err.Error(), "signature") {
			t.Errorf("Expected signature error, got: %v", err)
		}
	})

	t.Run("fails when not paired", func(t *testing.T) {
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

		err := runDecrypt(mgr, deviceKey, "", "", "http://example.com")
		if err == nil {
			t.Error("Expected error when not paired")
		}
		if !strings.Contains(err.Error(), "not paired") {
			t.Errorf("Expected 'not paired' error, got: %v", err)
		}
	})
}
