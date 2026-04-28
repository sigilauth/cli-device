package main

import (
	"fmt"

	"github.com/sigilauth/cli-device/internal/state"
)

func cmdUnpairWrapper(args []string) error {
	mgr := state.DefaultManager()
	return cmdUnpair(mgr)
}

func cmdUnpair(mgr *state.Manager) error {
	if !mgr.Exists() {
		return fmt.Errorf("device not initialized. Run 'sigil-device init' first")
	}

	st, err := mgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	if st.ServerURL == "" {
		return fmt.Errorf("device is not paired with any server")
	}

	fmt.Printf("Unpairing from: %s\n", st.ServerURL)

	// Clear server and relay info, keep device keypair
	st.ServerURL = ""
	st.ServerPublicKey = ""
	st.RelayURL = ""

	if err := mgr.Save(st); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	fmt.Println("✓ Unpaired successfully")
	fmt.Println("\nDevice identity preserved. You can pair with a new server using 'sigil-device pair'")

	return nil
}
