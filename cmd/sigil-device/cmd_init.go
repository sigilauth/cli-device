package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/pictogram"
	"github.com/sigilauth/cli-device/internal/state"
)

func runInit(mgr *state.Manager, force bool) error {
	// Check if state already exists
	if mgr.Exists() && !force {
		return fmt.Errorf("device already initialized (state already exists). Use --force to reinitialize")
	}

	// Generate 24-word BIP39 mnemonic (256 bits entropy)
	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		return fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// Derive ECDSA key from mnemonic
	privKey, err := crypto.DeriveServerKeypair(mnemonic)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Compress public key
	compressedPubKey := crypto.CompressPublicKey(&privKey.PublicKey)
	devicePublicKey := hex.EncodeToString(compressedPubKey)

	// Calculate fingerprint
	fingerprint := state.FingerprintFromPublicKey(&privKey.PublicKey)

	// Derive pictogram
	pictogramEmojis, speakable := pictogram.FromFingerprint(fingerprint)

	// Create state
	st := &state.State{
		DevicePublicKey:    devicePublicKey,
		Fingerprint:        fingerprint,
		Pictogram:          pictogramEmojis,
		PictogramSpeakable: speakable,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
	}

	// Save state.json
	if err := mgr.Save(st); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	// Save mnemonic.txt
	if err := mgr.SaveMnemonic(mnemonic); err != nil {
		return fmt.Errorf("failed to save mnemonic: %w", err)
	}

	return nil
}

func cmdInit(args []string) error {
	force := false
	for _, arg := range args {
		if arg == "--force" || arg == "-f" {
			force = true
		}
	}

	mgr := state.DefaultManager()
	return runInit(mgr, force)
}

// Private key is NOT persisted — always derived from mnemonic on demand
func loadPrivateKey(mgr *state.Manager) (*ecdsa.PrivateKey, error) {
	mnemonic, err := mgr.LoadMnemonic()
	if err != nil {
		return nil, fmt.Errorf("failed to load mnemonic: %w", err)
	}

	privKey, err := crypto.DeriveServerKeypair(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return privKey, nil
}
