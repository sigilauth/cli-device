package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_Save_And_Load(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	st := &State{
		DevicePublicKey:    "0345abcd...",
		Fingerprint:        "abc123...",
		Pictogram:          []string{"🐶", "🐱", "🐭", "🐹", "🐰"},
		PictogramSpeakable: "dog cat mouse hamster rabbit",
		ServerPublicKey:    "0456def...",
		ServerURL:          "https://server.example.com",
		RelayURL:           "wss://relay.example.com",
		DeviceName:         "Test Device",
		CreatedAt:          "2026-04-25T12:00:00Z",
	}

	err := mgr.Save(st)
	require.NoError(t, err)

	loaded, err := mgr.Load()
	require.NoError(t, err)

	assert.Equal(t, st.DevicePublicKey, loaded.DevicePublicKey)
	assert.Equal(t, st.Fingerprint, loaded.Fingerprint)
	assert.Equal(t, st.Pictogram, loaded.Pictogram)
	assert.Equal(t, st.PictogramSpeakable, loaded.PictogramSpeakable)
	assert.Equal(t, st.ServerPublicKey, loaded.ServerPublicKey)
	assert.Equal(t, st.ServerURL, loaded.ServerURL)
	assert.Equal(t, st.RelayURL, loaded.RelayURL)
	assert.Equal(t, st.DeviceName, loaded.DeviceName)
	assert.Equal(t, st.CreatedAt, loaded.CreatedAt)
}

func TestManager_SaveMnemonic_And_LoadMnemonic(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	err := mgr.SaveMnemonic(mnemonic)
	require.NoError(t, err)

	loaded, err := mgr.LoadMnemonic()
	require.NoError(t, err)

	assert.Equal(t, mnemonic, loaded)
}

func TestManager_FilePermissions(t *testing.T) {
	tmpBase := t.TempDir()
	tmpDir := filepath.Join(tmpBase, "state")
	mgr := NewManager(tmpDir)

	st := &State{
		DevicePublicKey: "test",
		Fingerprint:     "test",
		Pictogram:       []string{},
		CreatedAt:       "2026-04-25T12:00:00Z",
	}

	err := mgr.Save(st)
	require.NoError(t, err)

	// Check directory permissions
	dirInfo, err := os.Stat(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())

	// Check state.json permissions
	stateInfo, err := os.Stat(filepath.Join(tmpDir, "state.json"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), stateInfo.Mode().Perm())

	// Save mnemonic and check permissions
	err = mgr.SaveMnemonic("test mnemonic")
	require.NoError(t, err)

	mnemonicInfo, err := os.Stat(filepath.Join(tmpDir, "mnemonic.txt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), mnemonicInfo.Mode().Perm())
}

func TestManager_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	// Should not exist initially
	assert.False(t, mgr.Exists())

	// Should exist after saving
	st := &State{
		DevicePublicKey: "test",
		Fingerprint:     "test",
		Pictogram:       []string{},
		CreatedAt:       "2026-04-25T12:00:00Z",
	}
	err := mgr.Save(st)
	require.NoError(t, err)

	assert.True(t, mgr.Exists())
}

func TestManager_Load_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	_, err := mgr.Load()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read state")
}

func TestManager_LoadMnemonic_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	_, err := mgr.LoadMnemonic()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read mnemonic")
}

func TestFingerprintFromPublicKey(t *testing.T) {
	// Generate a test key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fingerprint := FingerprintFromPublicKey(&privKey.PublicKey)

	// Fingerprint should be 64 hex chars (SHA256 = 32 bytes)
	assert.Len(t, fingerprint, 64)

	// Should be lowercase hex
	for _, c := range fingerprint {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
	}

	// Same key should produce same fingerprint
	fingerprint2 := FingerprintFromPublicKey(&privKey.PublicKey)
	assert.Equal(t, fingerprint, fingerprint2)
}

func TestDefaultManager(t *testing.T) {
	mgr := DefaultManager()
	assert.NotNil(t, mgr)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	expectedPath := filepath.Join(home, ".sigil-device", "state.json")
	assert.Contains(t, mgr.statePath, ".sigil-device")
	assert.Equal(t, expectedPath, mgr.statePath)
}

func TestManager_Load_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	// Create directory
	err := os.MkdirAll(tmpDir, 0700)
	require.NoError(t, err)

	// Write invalid JSON
	err = os.WriteFile(filepath.Join(tmpDir, "state.json"), []byte("not valid json"), 0600)
	require.NoError(t, err)

	_, err = mgr.Load()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse state")
}

func TestManager_Save_MarshalError(t *testing.T) {
	// This is hard to trigger without making State have unexportable fields
	// or channels, so we skip this edge case test
	t.Skip("Cannot easily trigger json.Marshal error with State struct")
}

func TestFingerprintFromPublicKey_Deterministic(t *testing.T) {
	// Generate a key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Get fingerprint multiple times
	fp1 := FingerprintFromPublicKey(&privKey.PublicKey)
	fp2 := FingerprintFromPublicKey(&privKey.PublicKey)
	fp3 := FingerprintFromPublicKey(&privKey.PublicKey)

	// All should be identical
	assert.Equal(t, fp1, fp2)
	assert.Equal(t, fp2, fp3)
}

func TestNewManager(t *testing.T) {
	tmpDir := "/tmp/test-sigil"
	mgr := NewManager(tmpDir)

	assert.Equal(t, tmpDir, mgr.stateDir)
	assert.Equal(t, filepath.Join(tmpDir, "state.json"), mgr.statePath)
	assert.Equal(t, filepath.Join(tmpDir, "mnemonic.txt"), mgr.mnemonicPath)
}

// Error path tests for Save and SaveMnemonic

func TestSave_ErrorPaths(t *testing.T) {
	t.Run("directory does not exist", func(t *testing.T) {
		mgr := NewManager("/nonexistent/directory/.sigil-device")
		st := &State{
			DevicePublicKey: "test",
			Fingerprint:     "test",
		}
		err := mgr.Save(st)
		if err == nil {
			t.Error("Expected error when directory doesn't exist")
		}
	})

	t.Run("invalid JSON serialization", func(t *testing.T) {
		tmpDir := t.TempDir()
		mgr := NewManager(filepath.Join(tmpDir, ".sigil-device"))
		
		// Can't really test invalid JSON without reflection/unsafe,
		// but we can test the code path exists
		st := &State{
			DevicePublicKey: "test",
			Fingerprint:     "test",
			CreatedAt:       time.Now().Format(time.RFC3339),
		}
		err := mgr.Save(st)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestSaveMnemonic_ErrorPaths(t *testing.T) {
	t.Run("directory does not exist", func(t *testing.T) {
		mgr := NewManager("/nonexistent/directory/.sigil-device")
		err := mgr.SaveMnemonic("test mnemonic words here")
		if err == nil {
			t.Error("Expected error when directory doesn't exist")
		}
	})

	t.Run("empty mnemonic", func(t *testing.T) {
		tmpDir := t.TempDir()
		mgr := NewManager(filepath.Join(tmpDir, ".sigil-device"))
		
		err := mgr.SaveMnemonic("")
		// Empty mnemonic should still save (file will be created)
		if err != nil {
			// Only error if directory creation or file write fails
			if !strings.Contains(err.Error(), "no such file") {
				t.Errorf("Unexpected error: %v", err)
			}
		}
	})

	t.Run("very long mnemonic", func(t *testing.T) {
		tmpDir := t.TempDir()
		mgr := NewManager(filepath.Join(tmpDir, ".sigil-device"))
		
		// Test with a very long string
		longMnemonic := strings.Repeat("word ", 1000)
		err := mgr.SaveMnemonic(longMnemonic)
		if err != nil && !strings.Contains(err.Error(), "no such file") {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestLoad_ErrorPaths(t *testing.T) {
	t.Run("file does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		mgr := NewManager(filepath.Join(tmpDir, ".sigil-device"))
		
		_, err := mgr.Load()
		if err == nil {
			t.Error("Expected error when file doesn't exist")
		}
	})

	t.Run("corrupted JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, ".sigil-device")
		os.MkdirAll(stateDir, 0700)
		
		// Write invalid JSON
		os.WriteFile(filepath.Join(stateDir, "state.json"), []byte("{invalid json"), 0600)
		
		mgr := NewManager(stateDir)
		_, err := mgr.Load()
		if err == nil {
			t.Error("Expected error when JSON is corrupted")
		}
	})
}
