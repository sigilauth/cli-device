package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/state"
)

func TestRunListen_DeviceNotInitialized(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(filepath.Join(tmpDir, ".sigil-device"))

	err := runListen(mgr, "wss://relay.example.com", false)
	if err == nil {
		t.Error("Expected error when device not initialized")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("Expected 'not initialized' error, got: %v", err)
	}
}

func TestRunListen_InvalidRelayURL(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(filepath.Join(tmpDir, ".sigil-device"))

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	devicePubCompressed := crypto.CompressPublicKey(&deviceKey.PublicKey)
	devicePubHex := fmt.Sprintf("%x", devicePubCompressed)
	serverPubCompressed := crypto.CompressPublicKey(&serverKey.PublicKey)
	serverPubHex := fmt.Sprintf("%x", serverPubCompressed)

	fingerprint := sha256.Sum256(devicePubCompressed)
	fingerprintHex := fmt.Sprintf("%x", fingerprint[:])

	st := &state.State{
		DevicePublicKey: devicePubHex,
		ServerPublicKey: serverPubHex,
		Fingerprint:     fingerprintHex,
		Pictogram:       []string{"🐢", "🐊"},
		ServerURL:       "http://example.com",
		CreatedAt:       time.Now().Format(time.RFC3339),
	}
	mgr.Save(st)
	mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

	err := runListen(mgr, "not-a-valid-url", false)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestRunListen_ConnectionFailure(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(filepath.Join(tmpDir, ".sigil-device"))

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	devicePubCompressed := crypto.CompressPublicKey(&deviceKey.PublicKey)
	devicePubHex := fmt.Sprintf("%x", devicePubCompressed)
	serverPubCompressed := crypto.CompressPublicKey(&serverKey.PublicKey)
	serverPubHex := fmt.Sprintf("%x", serverPubCompressed)

	fingerprint := sha256.Sum256(devicePubCompressed)
	fingerprintHex := fmt.Sprintf("%x", fingerprint[:])

	st := &state.State{
		DevicePublicKey: devicePubHex,
		ServerPublicKey: serverPubHex,
		Fingerprint:     fingerprintHex,
		Pictogram:       []string{"🐢", "🐊"},
		ServerURL:       "http://example.com",
		CreatedAt:       time.Now().Format(time.RFC3339),
	}
	mgr.Save(st)
	mgr.SaveMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

	// Try to connect to non-existent server
	err := runListen(mgr, "ws://localhost:99999", false)
	if err == nil {
		t.Error("Expected connection error")
	}
}
