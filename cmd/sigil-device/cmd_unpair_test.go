package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigilauth/cli-device/internal/state"
)

func TestCmdUnpair(t *testing.T) {
	tests := []struct {
		name       string
		stateData  string
		wantErr    bool
		checkState func(*testing.T, *state.State)
	}{
		{
			name: "clears server and relay info",
			stateData: `{
				"device_public_key": "0251f1dfeba7f0d6349b20f7587d00cea77890d25828892872135a85ee87c92044",
				"fingerprint": "976f40610003b9d58e320d23dd1ef708066e407934b6c3bbe0280f2aa80e8254",
				"pictogram": ["🐢", "🐊", "🦛", "🐶", "🐗"],
				"pictogram_speakable": "turtle crocodile hippo dog boar",
				"server_url": "https://auth.example.com",
				"server_public_key": "0245d5a8f2e3b1c9d4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
				"relay_url": "http://relay.example.com",
				"created_at": "2026-04-26T03:33:34Z"
			}`,
			wantErr: false,
			checkState: func(t *testing.T, st *state.State) {
				if st.ServerURL != "" {
					t.Errorf("Expected server_url to be cleared, got %q", st.ServerURL)
				}
				if st.ServerPublicKey != "" {
					t.Errorf("Expected server_public_key to be cleared, got %q", st.ServerPublicKey)
				}
				if st.RelayURL != "" {
					t.Errorf("Expected relay_url to be cleared, got %q", st.RelayURL)
				}
				// Device keypair should remain
				if st.DevicePublicKey != "0251f1dfeba7f0d6349b20f7587d00cea77890d25828892872135a85ee87c92044" {
					t.Errorf("Device public key was modified")
				}
				if st.Fingerprint != "976f40610003b9d58e320d23dd1ef708066e407934b6c3bbe0280f2aa80e8254" {
					t.Errorf("Fingerprint was modified")
				}
			},
		},
		{
			name: "keeps device keypair intact",
			stateData: `{
				"device_public_key": "0251f1dfeba7f0d6349b20f7587d00cea77890d25828892872135a85ee87c92044",
				"fingerprint": "976f40610003b9d58e320d23dd1ef708066e407934b6c3bbe0280f2aa80e8254",
				"pictogram": ["🐢", "🐊", "🦛", "🐶", "🐗"],
				"pictogram_speakable": "turtle crocodile hippo dog boar",
				"server_url": "https://auth.example.com",
				"created_at": "2026-04-26T03:33:34Z"
			}`,
			wantErr: false,
			checkState: func(t *testing.T, st *state.State) {
				if st.DevicePublicKey == "" {
					t.Error("Device public key was cleared")
				}
				if len(st.Pictogram) == 0 {
					t.Error("Pictogram was cleared")
				}
			},
		},
		{
			name: "fails when not paired",
			stateData: `{
				"device_public_key": "0251f1dfeba7f0d6349b20f7587d00cea77890d25828892872135a85ee87c92044",
				"fingerprint": "976f40610003b9d58e320d23dd1ef708066e407934b6c3bbe0280f2aa80e8254",
				"pictogram": ["🐢", "🐊", "🦛", "🐶", "🐗"],
				"pictogram_speakable": "turtle crocodile hippo dog boar",
				"created_at": "2026-04-26T03:33:34Z"
			}`,
			wantErr: true,
			checkState: nil,
		},
		{
			name:       "fails when not initialized",
			stateData:  "",
			wantErr:    true,
			checkState: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			stateDir := filepath.Join(tmpDir, ".sigil-device")
			mgr := state.NewManager(stateDir)

			if tt.stateData != "" {
				if err := os.MkdirAll(stateDir, 0700); err != nil {
					t.Fatalf("Failed to create state dir: %v", err)
				}
				statePath := filepath.Join(stateDir, "state.json")
				if err := os.WriteFile(statePath, []byte(tt.stateData), 0600); err != nil {
					t.Fatalf("Failed to write test state: %v", err)
				}
			}

			err := cmdUnpair(mgr)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.checkState != nil {
				st, err := mgr.Load()
				if err != nil {
					t.Fatalf("Failed to load state after unpair: %v", err)
				}
				tt.checkState(t, st)
			}
		})
	}
}
