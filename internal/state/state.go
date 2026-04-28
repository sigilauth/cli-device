package state

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// State represents the device state stored on disk
type State struct {
	DevicePublicKey  string `json:"device_public_key"`
	Fingerprint      string `json:"fingerprint"`
	Pictogram        []string `json:"pictogram"`
	PictogramSpeakable string `json:"pictogram_speakable"`
	ServerPublicKey  string `json:"server_public_key,omitempty"`
	ServerURL        string `json:"server_url,omitempty"`
	RelayURL         string `json:"relay_url,omitempty"`
	DeviceName       string `json:"device_name,omitempty"`
	CreatedAt        string `json:"created_at"`
}

// Manager handles state file operations
type Manager struct {
	stateDir  string
	statePath string
	mnemonicPath string
}

// NewManager creates a new state manager
func NewManager(stateDir string) *Manager {
	return &Manager{
		stateDir:     stateDir,
		statePath:    filepath.Join(stateDir, "state.json"),
		mnemonicPath: filepath.Join(stateDir, "mnemonic.txt"),
	}
}

// DefaultManager returns a manager using ~/.sigil-device
func DefaultManager() *Manager {
	home, _ := os.UserHomeDir()
	return NewManager(filepath.Join(home, ".sigil-device"))
}

// Exists checks if state file exists
func (m *Manager) Exists() bool {
	_, err := os.Stat(m.statePath)
	return err == nil
}

// Load reads the state from disk
func (m *Manager) Load() (*State, error) {
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read state: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state: %w", err)
	}

	return &state, nil
}

// Save writes the state to disk with 0600 permissions
func (m *Manager) Save(state *State) error {
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(m.statePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}

	return nil
}

// SaveMnemonic writes the mnemonic backup with 0600 permissions
func (m *Manager) SaveMnemonic(mnemonic string) error {
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	if err := os.WriteFile(m.mnemonicPath, []byte(mnemonic), 0600); err != nil {
		return fmt.Errorf("failed to write mnemonic: %w", err)
	}

	return nil
}

// LoadMnemonic reads the mnemonic from disk
func (m *Manager) LoadMnemonic() (string, error) {
	data, err := os.ReadFile(m.mnemonicPath)
	if err != nil {
		return "", fmt.Errorf("failed to read mnemonic: %w", err)
	}

	return string(data), nil
}

// FingerprintFromPublicKey derives the fingerprint from a public key
func FingerprintFromPublicKey(pubKey *ecdsa.PublicKey) string {
	// Compressed format: 0x02/0x03 + X coordinate
	compressed := make([]byte, 33)
	pubKey.X.FillBytes(compressed[1:33])
	if pubKey.Y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}

	// SHA256 hash
	hash := sha256Sum(compressed)
	return hex.EncodeToString(hash[:])
}
