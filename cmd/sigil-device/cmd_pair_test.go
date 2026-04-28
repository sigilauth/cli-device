package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/pictogram"
	"github.com/sigilauth/cli-device/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPairCommand_Success(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 pair flow (GET /pair/init + session pictogram + POST /pair/complete)")

	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/info", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		// Generate a test server keypair
		serverPrivKey, err := crypto.DeriveServerKeypair("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
		require.NoError(t, err)

		serverPubKey := crypto.CompressPublicKey(&serverPrivKey.PublicKey)
		serverPubKeyHex := hex.EncodeToString(serverPubKey)
		serverFingerprint := state.FingerprintFromPublicKey(&serverPrivKey.PublicKey)

		// Derive correct pictogram from fingerprint
		serverPictogram, serverSpeakable := pictogram.FromFingerprint(serverFingerprint)

		response := map[string]interface{}{
			"server_id":                  serverFingerprint,
			"server_public_key":          serverPubKeyHex,
			"server_pictogram":           serverPictogram,
			"server_pictogram_speakable": serverSpeakable,
			"version":                    "0.1.0",
			"mode":                       "operational",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Initialize device first
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	// Run pair command
	err = runPair(mgr, server.URL)
	assert.NoError(t, err)

	// Verify state was updated
	st, err := mgr.Load()
	require.NoError(t, err)

	assert.NotEmpty(t, st.ServerPublicKey)
	assert.Equal(t, server.URL, st.ServerURL)
}

func TestPairCommand_StoresPictogram(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 pair flow")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverPrivKey, _ := crypto.DeriveServerKeypair("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote")
		serverPubKey := crypto.CompressPublicKey(&serverPrivKey.PublicKey)
		serverFingerprint := state.FingerprintFromPublicKey(&serverPrivKey.PublicKey)
		serverPictogram, serverSpeakable := pictogram.FromFingerprint(serverFingerprint)

		response := map[string]interface{}{
			"server_id":                  serverFingerprint,
			"server_public_key":          hex.EncodeToString(serverPubKey),
			"server_pictogram":           serverPictogram,
			"server_pictogram_speakable": serverSpeakable,
			"version":                    "0.1.0",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	err = runPair(mgr, server.URL)
	require.NoError(t, err)

	st, err := mgr.Load()
	require.NoError(t, err)

	assert.Len(t, st.Pictogram, 5, "Device pictogram should remain unchanged")
	// Server pictogram is displayed to user but not stored in state (design decision)
}

func TestPairCommand_FailsIfNotInitialized(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	err := runPair(mgr, "https://example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestPairCommand_ValidatesServerURL(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		serverURL string
		wantError bool
	}{
		{
			name:      "Valid HTTPS URL",
			serverURL: "https://server.example.com",
			wantError: false,
		},
		{
			name:      "Valid HTTP localhost",
			serverURL: "http://localhost:8080",
			wantError: false,
		},
		{
			name:      "Invalid - no scheme",
			serverURL: "server.example.com",
			wantError: true,
		},
		{
			name:      "Invalid - empty",
			serverURL: "",
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServerURL(tc.serverURL)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPairCommand_HandlesNetworkErrors(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 pair flow")

	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	// Invalid server URL - connection should fail
	err = runPair(mgr, "http://localhost:1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to")
}

func TestPairCommand_HandlesInvalidJSON(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 pair flow")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	err = runPair(mgr, server.URL)
	assert.Error(t, err)
}

func TestPairCommand_ValidatesServerResponse(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 pair flow")

	testCases := []struct {
		name      string
		response  map[string]interface{}
		wantError string
	}{
		{
			name: "Missing server_public_key",
			response: map[string]interface{}{
				"server_id": "abc123",
			},
			wantError: "server_public_key",
		},
		{
			name: "Invalid public key format",
			response: map[string]interface{}{
				"server_public_key": "not-hex",
				"server_id":         "abc123",
			},
			wantError: "invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tc.response)
			}))
			defer server.Close()

			tmpDir := t.TempDir()
			mgr := state.NewManager(tmpDir)
			err := runInit(mgr, false)
			require.NoError(t, err)

			err = runPair(mgr, server.URL)
			assert.Error(t, err)
			if tc.wantError != "" {
				assert.Contains(t, err.Error(), tc.wantError)
			}
		})
	}
}

func TestCmdPair_ParsesFlags(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 pair flow")

	// Save original HOME
	originalHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	// Init first
	err := cmdInit([]string{})
	require.NoError(t, err)

	// Start mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverPrivKey, _ := crypto.DeriveServerKeypair("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
		serverPubKey := crypto.CompressPublicKey(&serverPrivKey.PublicKey)
		serverFingerprint := state.FingerprintFromPublicKey(&serverPrivKey.PublicKey)
		serverPictogram, serverSpeakable := pictogram.FromFingerprint(serverFingerprint)

		response := map[string]interface{}{
			"server_id":                  serverFingerprint,
			"server_public_key":          hex.EncodeToString(serverPubKey),
			"server_pictogram":           serverPictogram,
			"server_pictogram_speakable": serverSpeakable,
			"version":                    "0.1.0",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Test --server flag
	err = cmdPair([]string{"--server", server.URL})
	assert.NoError(t, err)

	// Verify pairing worked
	mgr := state.DefaultManager()
	st, err := mgr.Load()
	require.NoError(t, err)
	assert.Equal(t, server.URL, st.ServerURL)
}

func TestCmdPair_RequiresServerFlag(t *testing.T) {
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Unsetenv("HOME")

	err := cmdInit([]string{})
	require.NoError(t, err)

	// No --server flag should fail
	err = cmdPair([]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server")
}
