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

func TestCmdRespond(t *testing.T) {
	// Generate server keypair
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverPubKeyCompressed := crypto.CompressPublicKey(&serverKey.PublicKey)
	serverPubKeyHex := fmt.Sprintf("%x", serverPubKeyCompressed)

	// Generate device keypair
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devicePubKeyCompressed := crypto.CompressPublicKey(&deviceKey.PublicKey)
	devicePubKeyHex := fmt.Sprintf("%x", devicePubKeyCompressed)

	fingerprint := sha256.Sum256(devicePubKeyCompressed)
	fingerprintHex := fmt.Sprintf("%x", fingerprint[:])

	t.Run("responds to valid challenge from file", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol (POST /envelope)")

		// Create mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/respond" {
				http.Error(w, "not found", 404)
				return
			}

			var req map[string]string
			json.NewDecoder(r.Body).Decode(&req)

			// Verify we got challenge_id and signature
			if req["challenge_id"] == "" || req["signature"] == "" {
				http.Error(w, "missing fields", 400)
				return
			}

			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "verified",
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
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)

		// Save device private key
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		mgr.SaveMnemonic(mnemonic)

		// Create challenge file
		challengeBytes := make([]byte, 32)
		rand.Read(challengeBytes)

		// Server signs the challenge (V1 format: domain-separated with empty action_context)
		actionHash, _ := crypto.ComputeActionContextHash(nil)
		message := append(challengeBytes, actionHash...)
		serverSig, _ := crypto.SignWithDomain(serverKey, crypto.DomainAuth, message)

		challenge := map[string]string{
			"challenge_id":     "test-123",
			"challenge":        base64.StdEncoding.EncodeToString(challengeBytes),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		challengeFile := filepath.Join(tmpDir, "challenge.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		// Run respond command
		err := runRespond(mgr, deviceKey, challengeFile, "", server.URL)
		if err != nil {
			t.Errorf("runRespond failed: %v", err)
		}
	})

	t.Run("rejects challenge with invalid server signature", func(t *testing.T) {
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
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		// Create challenge with invalid signature (signed by wrong key)
		wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		challengeBytes := make([]byte, 32)
		rand.Read(challengeBytes)
		actionHash, _ := crypto.ComputeActionContextHash(nil)
		message := append(challengeBytes, actionHash...)
		wrongSig, _ := crypto.SignWithDomain(wrongKey, crypto.DomainAuth, message)

		challenge := map[string]string{
			"challenge_id":     "test-456",
			"challenge":        base64.StdEncoding.EncodeToString(challengeBytes),
			"server_signature": base64.StdEncoding.EncodeToString(wrongSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		challengeFile := filepath.Join(tmpDir, "bad-challenge.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		// Should fail with invalid signature error
		err := runRespond(mgr, deviceKey, challengeFile, "", "http://example.com")
		if err == nil {
			t.Error("Expected error for invalid server signature")
		}
		if !strings.Contains(err.Error(), "invalid signature") && !strings.Contains(err.Error(), "server signature verification failed") {
			t.Errorf("Expected signature error, got: %v", err)
		}
	})

	t.Run("reads challenge from stdin", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
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
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challengeBytes := make([]byte, 32)
		rand.Read(challengeBytes)
		actionHash, _ := crypto.ComputeActionContextHash(nil)
		message := append(challengeBytes, actionHash...)
		serverSig, _ := crypto.SignWithDomain(serverKey, crypto.DomainAuth, message)

		challenge := map[string]string{
			"challenge_id":     "stdin-test",
			"challenge":        base64.StdEncoding.EncodeToString(challengeBytes),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		challengeJSON, _ := json.MarshalIndent(challenge, "", "  ")

		// Write to temp file to simulate stdin
		stdinFile := filepath.Join(tmpDir, "stdin.json")
		os.WriteFile(stdinFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, "", stdinFile, server.URL)
		if err != nil {
			t.Errorf("runRespond from stdin failed: %v", err)
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

		err := runRespond(mgr, deviceKey, "", "", "http://example.com")
		if err == nil {
			t.Error("Expected error when not paired")
		}
		if !strings.Contains(err.Error(), "not paired") {
			t.Errorf("Expected 'not paired' error, got: %v", err)
		}
	})

	t.Run("rejects challenge missing required fields", func(t *testing.T) {
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://example.com",
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		// Missing server_signature field
		challenge := map[string]string{
			"challenge_id": "incomplete",
			"challenge":    base64.StdEncoding.EncodeToString([]byte("test")),
		}

		challengeFile := filepath.Join(tmpDir, "incomplete.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", "http://example.com")
		if err == nil {
			t.Error("Expected error for missing fields")
		}
		if !strings.Contains(err.Error(), "missing required fields") {
			t.Errorf("Expected 'missing required fields' error, got: %v", err)
		}
	})

	t.Run("handles server POST failure (500)", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal server error", 500)
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
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challengeBytes := make([]byte, 32)
		rand.Read(challengeBytes)
		actionHash, _ := crypto.ComputeActionContextHash(nil)
		message := append(challengeBytes, actionHash...)
		serverSig, _ := crypto.SignWithDomain(serverKey, crypto.DomainAuth, message)

		challenge := map[string]string{
			"challenge_id":     "error-test",
			"challenge":        base64.StdEncoding.EncodeToString(challengeBytes),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		challengeFile := filepath.Join(tmpDir, "error.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", server.URL)
		if err == nil {
			t.Error("Expected error for server 500")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("Expected 500 error, got: %v", err)
		}
	})

	t.Run("handles invalid challenge JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://example.com",
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challengeFile := filepath.Join(tmpDir, "invalid.json")
		os.WriteFile(challengeFile, []byte("not valid json{{{"), 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", "http://example.com")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "parse") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})

	t.Run("handles invalid challenge base64", func(t *testing.T) {
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://example.com",
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challenge := map[string]string{
			"challenge_id":     "bad-base64",
			"challenge":        "!!!invalid base64!!!",
			"server_signature": base64.StdEncoding.EncodeToString([]byte("fake")),
		}

		challengeFile := filepath.Join(tmpDir, "badbase64.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", "http://example.com")
		if err == nil {
			t.Error("Expected error for invalid base64")
		}
		if !strings.Contains(err.Error(), "decode challenge") {
			t.Errorf("Expected decode error, got: %v", err)
		}
	})

	t.Run("handles network unreachable", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://127.0.0.1:9999",
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challengeBytes := make([]byte, 32)
		rand.Read(challengeBytes)
		actionHash, _ := crypto.ComputeActionContextHash(nil)
		message := append(challengeBytes, actionHash...)
		serverSig, _ := crypto.SignWithDomain(serverKey, crypto.DomainAuth, message)

		challenge := map[string]string{
			"challenge_id":     "network-fail",
			"challenge":        base64.StdEncoding.EncodeToString(challengeBytes),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		challengeFile := filepath.Join(tmpDir, "network.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", "http://127.0.0.1:9999")
		if err == nil {
			t.Error("Expected error for network unreachable")
		}
		if !strings.Contains(err.Error(), "POST") {
			t.Errorf("Expected POST error, got: %v", err)
		}
	})

	t.Run("handles invalid signature base64", func(t *testing.T) {
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://example.com",
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challenge := map[string]string{
			"challenge_id":     "bad-sig",
			"challenge":        base64.StdEncoding.EncodeToString([]byte("test")),
			"server_signature": "!!!invalid!!!",
		}

		challengeFile := filepath.Join(tmpDir, "badsig.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", "http://example.com")
		if err == nil {
			t.Error("Expected error for invalid signature base64")
		}
		if !strings.Contains(err.Error(), "decode") && !strings.Contains(err.Error(), "signature") {
			t.Errorf("Expected decode error, got: %v", err)
		}
	})

	t.Run("handles signature wrong length", func(t *testing.T) {
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://example.com",
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challenge := map[string]string{
			"challenge_id":     "wrong-len",
			"challenge":        base64.StdEncoding.EncodeToString([]byte("test")),
			"server_signature": base64.StdEncoding.EncodeToString([]byte("short")),
		}

		challengeFile := filepath.Join(tmpDir, "wronglen.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", "http://example.com")
		if err == nil {
			t.Error("Expected error for wrong signature length")
		}
		if !strings.Contains(err.Error(), "64 bytes") {
			t.Errorf("Expected 64 bytes error, got: %v", err)
		}
	})

	t.Run("handles server response decode error", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("not json"))
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
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challengeBytes := make([]byte, 32)
		rand.Read(challengeBytes)
		actionHash, _ := crypto.ComputeActionContextHash(nil)
		message := append(challengeBytes, actionHash...)
		serverSig, _ := crypto.SignWithDomain(serverKey, crypto.DomainAuth, message)

		challenge := map[string]string{
			"challenge_id":     "decode-error",
			"challenge":        base64.StdEncoding.EncodeToString(challengeBytes),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		challengeFile := filepath.Join(tmpDir, "decodeerr.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", server.URL)
		if err == nil {
			t.Error("Expected error for response decode failure")
		}
		if !strings.Contains(err.Error(), "decode response") {
			t.Errorf("Expected decode response error, got: %v", err)
		}
	})

	t.Run("handles file read error", func(t *testing.T) {
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://example.com",
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		err := runRespond(mgr, deviceKey, "/nonexistent/file.json", "", "http://example.com")
		if err == nil {
			t.Error("Expected error for file not found")
		}
		if !strings.Contains(err.Error(), "read challenge file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("uses server URL from state when not provided", func(t *testing.T) {
		t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
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
			ServerPublicKey:    serverPubKeyHex,
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challengeBytes := make([]byte, 32)
		rand.Read(challengeBytes)
		actionHash, _ := crypto.ComputeActionContextHash(nil)
		message := append(challengeBytes, actionHash...)
		serverSig, _ := crypto.SignWithDomain(serverKey, crypto.DomainAuth, message)

		challenge := map[string]string{
			"challenge_id":     "fallback-url",
			"challenge":        base64.StdEncoding.EncodeToString(challengeBytes),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		challengeFile := filepath.Join(tmpDir, "fallback.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		// Pass empty serverURL to test fallback to st.ServerURL
		err := runRespond(mgr, deviceKey, challengeFile, "", "")
		if err != nil {
			t.Errorf("Should use server URL from state: %v", err)
		}
	})

	t.Run("handles invalid server public key in state", func(t *testing.T) {
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		mgr := state.NewManager(stateDir)

		st := &state.State{
			DevicePublicKey:    devicePubKeyHex,
			Fingerprint:        fingerprintHex,
			Pictogram:          []string{"🐢", "🐊", "🦛", "🐶", "🐗"},
			PictogramSpeakable: "turtle crocodile hippo dog boar",
			ServerURL:          "http://example.com",
			ServerPublicKey:    "zzzinvalid",
			CreatedAt:          "2026-04-26T00:00:00Z",
		}
		mgr.Save(st)
		mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

		challengeBytes := make([]byte, 32)
		rand.Read(challengeBytes)
		actionHash, _ := crypto.ComputeActionContextHash(nil)
		message := append(challengeBytes, actionHash...)
		serverSig, _ := crypto.SignWithDomain(serverKey, crypto.DomainAuth, message)

		challenge := map[string]string{
			"challenge_id":     "bad-pubkey",
			"challenge":        base64.StdEncoding.EncodeToString(challengeBytes),
			"server_signature": base64.StdEncoding.EncodeToString(serverSig),
			"expires_at":       "2026-04-26T12:00:00Z",
		}

		challengeFile := filepath.Join(tmpDir, "badpub.json")
		challengeJSON, _ := json.Marshal(challenge)
		os.WriteFile(challengeFile, challengeJSON, 0600)

		err := runRespond(mgr, deviceKey, challengeFile, "", "http://example.com")
		if err == nil {
			t.Error("Expected error for invalid server public key")
		}
		if !strings.Contains(err.Error(), "decode server public key") {
			t.Errorf("Expected decode error, got: %v", err)
		}
	})
}
