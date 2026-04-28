package main

import (
	"fmt"
	"strings"

	"github.com/sigilauth/cli-device/internal/state"
)

func cmdWhoamiWrapper(args []string) error {
	mgr := state.DefaultManager()
	return cmdWhoami(mgr)
}

func cmdWhoami(mgr *state.Manager) error {
	if !mgr.Exists() {
		return fmt.Errorf("device not initialized. Run 'sigil-device init' first")
	}

	st, err := mgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	fmt.Printf("Fingerprint: %s\n", st.Fingerprint)
	fmt.Printf("Pictogram:   %s\n", strings.Join(st.Pictogram, " "))
	fmt.Printf("Speakable:   %s\n", st.PictogramSpeakable)
	fmt.Println()

	if st.ServerURL != "" {
		fmt.Printf("Paired with: %s\n", st.ServerURL)
		if st.ServerPublicKey != "" {
			fmt.Printf("Server public key: %s\n", st.ServerPublicKey)
		}
	} else {
		fmt.Println("Not paired with any server")
	}

	if st.RelayURL != "" {
		fmt.Printf("\nRegistered with relay: %s\n", st.RelayURL)
	}

	return nil
}
