package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigilauth/cli-device/internal/state"
)

func TestCmdWhoami(t *testing.T) {
	tests := []struct {
		name      string
		stateData string
		wantErr   bool
	}{
		{
			name: "succeeds with minimal state",
			stateData: `{
				"device_public_key": "0251f1dfeba7f0d6349b20f7587d00cea77890d25828892872135a85ee87c92044",
				"fingerprint": "976f40610003b9d58e320d23dd1ef708066e407934b6c3bbe0280f2aa80e8254",
				"pictogram": ["🐢", "🐊", "🦛", "🐶", "🐗"],
				"pictogram_speakable": "turtle crocodile hippo dog boar",
				"created_at": "2026-04-26T03:33:34Z"
			}`,
			wantErr: false,
		},
		{
			name: "succeeds with paired state",
			stateData: `{
				"device_public_key": "0251f1dfeba7f0d6349b20f7587d00cea77890d25828892872135a85ee87c92044",
				"fingerprint": "976f40610003b9d58e320d23dd1ef708066e407934b6c3bbe0280f2aa80e8254",
				"pictogram": ["🐢", "🐊", "🦛", "🐶", "🐗"],
				"pictogram_speakable": "turtle crocodile hippo dog boar",
				"server_url": "https://auth.example.com",
				"server_public_key": "0245d5a8f2e3b1c9d4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
				"created_at": "2026-04-26T03:33:34Z"
			}`,
			wantErr: false,
		},
		{
			name: "succeeds with registered state",
			stateData: `{
				"device_public_key": "0251f1dfeba7f0d6349b20f7587d00cea77890d25828892872135a85ee87c92044",
				"fingerprint": "976f40610003b9d58e320d23dd1ef708066e407934b6c3bbe0280f2aa80e8254",
				"pictogram": ["🐢", "🐊", "🦛", "🐶", "🐗"],
				"pictogram_speakable": "turtle crocodile hippo dog boar",
				"relay_url": "http://relay.example.com",
				"created_at": "2026-04-26T03:33:34Z"
			}`,
			wantErr: false,
		},
		{
			name:      "fails when state file missing",
			stateData: "",
			wantErr:   true,
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

			err := cmdWhoami(mgr)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
