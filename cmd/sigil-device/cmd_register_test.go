package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sigilauth/cli-device/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterCommand_Success(t *testing.T) {
	// Setup mock relay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/devices/register", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var req map[string]string
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.NotEmpty(t, req["device_public_key"])
		assert.Equal(t, "websocket", req["push_platform"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "registered",
		})
	}))
	defer server.Close()

	// Initialize and pair device first
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	// Run register command
	err = runRegister(mgr, server.URL)
	assert.NoError(t, err)

	// Verify state was updated
	st, err := mgr.Load()
	require.NoError(t, err)

	assert.Equal(t, server.URL, st.RelayURL)
}

func TestRegisterCommand_SendsDevicePublicKey(t *testing.T) {
	var receivedPubKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		receivedPubKey = req["device_public_key"]

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	st, err := mgr.Load()
	require.NoError(t, err)

	err = runRegister(mgr, server.URL)
	require.NoError(t, err)

	// Verify sent public key matches device public key
	assert.Equal(t, st.DevicePublicKey, receivedPubKey)
}

func TestRegisterCommand_FailsIfNotInitialized(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)

	err := runRegister(mgr, "https://relay.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestRegisterCommand_ValidatesRelayURL(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		relayURL  string
		wantError bool
	}{
		{
			name:      "Valid HTTPS URL",
			relayURL:  "https://relay.example.com",
			wantError: false,
		},
		{
			name:      "Valid HTTP localhost",
			relayURL:  "http://localhost:8080",
			wantError: false,
		},
		{
			name:      "Invalid - no scheme",
			relayURL:  "relay.example.com",
			wantError: true,
		},
		{
			name:      "Invalid - empty",
			relayURL:  "",
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRelayURL(tc.relayURL)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRegisterCommand_HandlesRelayUnavailable(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	// Invalid relay URL - connection should fail
	err = runRegister(mgr, "http://localhost:1")
	assert.Error(t, err)
}

func TestRegisterCommand_HandlesInvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	err = runRegister(mgr, server.URL)
	assert.Error(t, err)
}

func TestRegisterCommand_HandlesHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	mgr := state.NewManager(tmpDir)
	err := runInit(mgr, false)
	require.NoError(t, err)

	err = runRegister(mgr, server.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestCmdRegister_ParsesFlags(t *testing.T) {
	// Save original HOME
	originalHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	// Init first
	err := cmdInit([]string{})
	require.NoError(t, err)

	// Start mock relay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
	}))
	defer server.Close()

	// Test --relay flag
	err = cmdRegister([]string{"--relay", server.URL})
	assert.NoError(t, err)

	// Verify registration worked
	mgr := state.DefaultManager()
	st, err := mgr.Load()
	require.NoError(t, err)
	assert.Equal(t, server.URL, st.RelayURL)
}

func TestCmdRegister_RequiresRelayFlag(t *testing.T) {
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Unsetenv("HOME")

	err := cmdInit([]string{})
	require.NoError(t, err)

	// No --relay flag should fail
	err = cmdRegister([]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "relay")
}
