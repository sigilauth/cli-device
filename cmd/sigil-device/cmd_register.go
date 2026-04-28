package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sigilauth/cli-device/internal/state"
)

func runRegister(mgr *state.Manager, relayURL string) error {
	// Check if device is initialized
	if !mgr.Exists() {
		return fmt.Errorf("device not initialized. Run 'sigil-device init' first")
	}

	// Validate relay URL
	if err := validateRelayURL(relayURL); err != nil {
		return err
	}

	// Load current state
	st, err := mgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Prepare registration request
	reqBody := map[string]string{
		"device_public_key": st.DevicePublicKey,
		"push_platform":     "websocket",
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send registration request
	registerURL := relayURL + "/devices/register"
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(registerURL, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return fmt.Errorf("failed to connect to relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("relay returned %d: %s", resp.StatusCode, string(body))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to parse relay response: %w", err)
	}

	// Update state with relay URL
	st.RelayURL = relayURL

	if err := mgr.Save(st); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	fmt.Printf("\n✓ Registered with relay: %s\n", relayURL)
	fmt.Printf("Device fingerprint: %s\n", st.Fingerprint)
	fmt.Printf("Push platform: websocket\n\n")

	return nil
}

func validateRelayURL(relayURL string) error {
	if relayURL == "" {
		return fmt.Errorf("relay URL is required")
	}

	u, err := url.Parse(relayURL)
	if err != nil {
		return fmt.Errorf("invalid relay URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("relay URL must use http:// or https://")
	}

	if u.Host == "" {
		return fmt.Errorf("relay URL must include host")
	}

	return nil
}

func cmdRegister(args []string) error {
	relayURL := ""

	// Parse flags
	for i := 0; i < len(args); i++ {
		if args[i] == "--relay" || args[i] == "-r" {
			if i+1 >= len(args) {
				return fmt.Errorf("--relay flag requires a URL argument")
			}
			relayURL = args[i+1]
			i++
		}
	}

	if relayURL == "" {
		return fmt.Errorf("--relay flag is required. Usage: sigil-device register --relay <url>")
	}

	mgr := state.DefaultManager()
	return runRegister(mgr, relayURL)
}
