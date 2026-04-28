package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/pictogram"
	"github.com/sigilauth/cli-device/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitCommand_CreatesStateJSON(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	err := runInit(mgr, false)
	require.NoError(t, err)

	// Verify state.json exists
	statePath := filepath.Join(tmpDir, "state.json")
	require.FileExists(t, statePath)

	// Verify file permissions are 0600
	info, err := os.Stat(statePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Load and verify structure
	st, err := mgr.Load()
	require.NoError(t, err)
	assert.NotEmpty(t, st.DevicePublicKey)
	assert.NotEmpty(t, st.Fingerprint)
	assert.Len(t, st.Pictogram, 5)
	assert.NotEmpty(t, st.PictogramSpeakable)
	assert.NotEmpty(t, st.CreatedAt)
}

func TestInitCommand_CreatesMnemonicFile(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	err := runInit(mgr, false)
	require.NoError(t, err)

	// Verify mnemonic.txt exists
	mnemonicPath := filepath.Join(tmpDir, "mnemonic.txt")
	require.FileExists(t, mnemonicPath)

	// Verify file permissions are 0600
	info, err := os.Stat(mnemonicPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Load and verify it's 24 words
	mnemonic, err := mgr.LoadMnemonic()
	require.NoError(t, err)
	words := strings.Fields(mnemonic)
	assert.Len(t, words, 24)

	// Verify it's valid BIP39 (reconstructing to validate checksum)
	_, err = crypto.MnemonicToEntropy(mnemonic)
	assert.NoError(t, err)
}

func TestInitCommand_FingerprintMatchesSHA256PublicKey(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	err := runInit(mgr, false)
	require.NoError(t, err)

	st, err := mgr.Load()
	require.NoError(t, err)

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(st.DevicePublicKey)
	require.NoError(t, err)

	pubKey, err := crypto.DecompressPublicKey(pubKeyBytes)
	require.NoError(t, err)

	// Calculate expected fingerprint
	expectedFingerprint := state.FingerprintFromPublicKey(pubKey)
	assert.Equal(t, expectedFingerprint, st.Fingerprint)
}

func TestInitCommand_PictogramMatchesProtocolSpec(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	err := runInit(mgr, false)
	require.NoError(t, err)

	st, err := mgr.Load()
	require.NoError(t, err)

	// Verify pictogram is 5 emojis
	assert.Len(t, st.Pictogram, 5)

	// Verify each element is a valid emoji from the canonical protocol spec
	validEmojis := pictogram.EmojiList[:]

	for _, emoji := range st.Pictogram {
		assert.Contains(t, validEmojis, emoji)
	}

	// Verify speakable format
	assert.NotEmpty(t, st.PictogramSpeakable)
}

func TestInitCommand_FilePermissions(t *testing.T) {
	// Create a custom temp directory that doesn't exist yet
	// so state.Manager will create it with 0700
	tmpBase := t.TempDir()
	tmpDir := filepath.Join(tmpBase, "state")
	mgr := state.NewManager(tmpDir)

	err := runInit(mgr, false)
	require.NoError(t, err)

	// Check state.json permissions
	stateInfo, err := os.Stat(filepath.Join(tmpDir, "state.json"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), stateInfo.Mode().Perm())

	// Check mnemonic.txt permissions
	mnemonicInfo, err := os.Stat(filepath.Join(tmpDir, "mnemonic.txt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), mnemonicInfo.Mode().Perm())

	// Check directory permissions (created by state.Manager)
	dirInfo, err := os.Stat(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())
}

func TestInitCommand_FailsIfStateExists(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	// First init should succeed
	err := runInit(mgr, false)
	require.NoError(t, err)

	// Second init without --force should fail
	err = runInit(mgr, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// With --force should succeed
	err = runInit(mgr, true)
	assert.NoError(t, err)
}

func TestCmdInit_NoArgs(t *testing.T) {
	// Note: This test uses the actual DefaultManager path
	// We can't easily override it without refactoring, so we just test the parse logic
	// by ensuring the function signature works

	// Save original HOME to restore after test
	originalHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	err := cmdInit([]string{})
	require.NoError(t, err)

	// Verify state was created
	mgr := state.DefaultManager()
	assert.True(t, mgr.Exists())
}

func TestCmdInit_WithForceFlag(t *testing.T) {
	// Save original HOME to restore after test
	originalHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	// First init
	err := cmdInit([]string{})
	require.NoError(t, err)

	// Second init should fail without --force
	err = cmdInit([]string{})
	assert.Error(t, err)

	// Should succeed with --force
	err = cmdInit([]string{"--force"})
	assert.NoError(t, err)

	// Should also work with -f
	err = cmdInit([]string{"-f"})
	assert.NoError(t, err)
}

func TestLoadPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	// Initialize device first
	err := runInit(mgr, false)
	require.NoError(t, err)

	// Load private key
	privKey, err := loadPrivateKey(mgr)
	require.NoError(t, err)
	assert.NotNil(t, privKey)

	// Verify it's a valid ECDSA key
	assert.NotNil(t, privKey.D)
	assert.NotNil(t, privKey.PublicKey.X)
	assert.NotNil(t, privKey.PublicKey.Y)

	// Load state and verify public key matches
	st, err := mgr.Load()
	require.NoError(t, err)

	pubKeyBytes, err := hex.DecodeString(st.DevicePublicKey)
	require.NoError(t, err)

	expectedPubKey, err := crypto.DecompressPublicKey(pubKeyBytes)
	require.NoError(t, err)

	assert.Equal(t, expectedPubKey.X, privKey.PublicKey.X)
	assert.Equal(t, expectedPubKey.Y, privKey.PublicKey.Y)
}

func TestLoadPrivateKey_NoMnemonic(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	_, err := loadPrivateKey(mgr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load mnemonic")
}
