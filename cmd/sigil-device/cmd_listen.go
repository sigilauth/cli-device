package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/listener"
	"github.com/sigilauth/cli-device/internal/state"
)

func runListen(mgr *state.Manager, relayURL string, autoApprove bool) error {
	// Check if device is initialized and registered
	if !mgr.Exists() {
		return fmt.Errorf("device not initialized. Run 'sigil-device init' first")
	}

	st, err := mgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	if st.RelayURL == "" && relayURL == "" {
		return fmt.Errorf("not registered with relay. Run 'sigil-device register --relay <url>' first or specify --relay")
	}

	// Use provided relay URL or fall back to registered one
	if relayURL == "" {
		relayURL = st.RelayURL
	}

	// Construct WebSocket URL
	wsURL := relayURL + "/ws"

	// Load private key
	privKey, err := loadPrivateKey(mgr)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Decode server public key from state
	if st.ServerPublicKey == "" {
		return fmt.Errorf("device not paired with server. Run 'sigil-device pair' first")
	}

	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(st.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode server public key: %w", err)
	}

	serverPubKey, err := crypto.DecompressPublicKey(serverPubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to decompress server public key: %w", err)
	}

	// Create WebSocket client
	client := listener.NewClient(wsURL, privKey, serverPubKey)

	// Set up challenge handler
	client.OnChallenge(func(challenge listener.Challenge) error {
		fmt.Printf("\n[%s] Received %s\n", challenge.ChallengeID, challenge.Type)

		if !autoApprove {
			fmt.Print("Approve? (y/N): ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Challenge rejected")
				return nil
			}
		}

		fmt.Println("Challenge approved (auto-approve mode)")
		// TODO: Sign and respond to challenge
		return nil
	})

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\nShutting down...")
		cancel()
	}()

	// Connect
	fmt.Printf("Connecting to %s...\n", wsURL)
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	fmt.Printf("✓ Connected and authenticated\n")
	fmt.Printf("Fingerprint: %s\n", st.Fingerprint)
	fmt.Printf("Listening for challenges... (Ctrl+C to stop)\n\n")

	// Wait for shutdown signal
	<-ctx.Done()

	client.Close()
	fmt.Println("Disconnected")

	return nil
}

func cmdListen(args []string) error {
	relayURL := ""
	autoApprove := false

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--relay", "-r":
			if i+1 >= len(args) {
				return fmt.Errorf("--relay flag requires a URL argument")
			}
			relayURL = args[i+1]
			i++
		case "--auto-approve", "-a":
			autoApprove = true
		}
	}

	mgr := state.DefaultManager()
	return runListen(mgr, relayURL, autoApprove)
}
