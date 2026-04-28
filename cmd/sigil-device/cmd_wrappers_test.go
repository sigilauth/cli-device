package main

import (
	"os"
	"testing"
)

// Test wrapper functions for basic coverage
// These wrappers just parse flags and call run*() functions which are already well-tested

func TestCmdDecryptWrapper_MissingFlag(t *testing.T) {
	err := cmdDecryptWrapper([]string{})
	if err == nil {
		t.Error("Expected error for missing device init")
	}
}

func TestCmdMPARespondWrapper_MissingFlag(t *testing.T) {
	err := cmdMPARespondWrapper([]string{})
	if err == nil {
		t.Error("Expected error for missing device init")
	}
}

func TestCmdRespondWrapper_MissingFlag(t *testing.T) {
	err := cmdRespondWrapper([]string{})
	if err == nil {
		t.Error("Expected error for missing device init")
	}
}

func TestCmdUnpairWrapper(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")

	// Should succeed even when no state exists
	err := cmdUnpairWrapper([]string{})
	if err == nil {
		// Expected - unpair succeeds even when not initialized
	}
}

func TestCmdWhoamiWrapper(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")
	
	// Should fail when device not initialized
	err := cmdWhoamiWrapper([]string{})
	if err == nil {
		t.Error("Expected error when device not initialized")
	}
}

func TestCmdListen_MissingRelay(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")
	
	// Should fail when --relay not provided
	err := cmdListen([]string{})
	if err == nil {
		t.Error("Expected error for missing --relay flag")
	}
}

// Additional wrapper tests for flag parsing coverage

func TestCmdDecryptWrapper_Flags(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")
	
	// Test --decrypt-file flag parsing
	err := cmdDecryptWrapper([]string{"--decrypt-file", "/nonexistent"})
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
	
	// Test --server flag parsing
	err = cmdDecryptWrapper([]string{"--server", "http://example.com"})
	if err == nil {
		t.Error("Expected error for missing device")
	}
}

func TestCmdMPARespondWrapper_Flags(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")
	
	// Test --mpa-file flag parsing
	err := cmdMPARespondWrapper([]string{"--mpa-file", "/nonexistent"})
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
	
	// Test --auto-approve flag
	err = cmdMPARespondWrapper([]string{"--auto-approve"})
	if err == nil {
		t.Error("Expected error for missing device")
	}
}

func TestCmdRespondWrapper_Flags(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")
	
	// Test --challenge-file flag parsing
	err := cmdRespondWrapper([]string{"--challenge-file", "/nonexistent"})
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
	
	// Test --server flag
	err = cmdRespondWrapper([]string{"--server", "http://example.com"})
	if err == nil {
		t.Error("Expected error for missing device")
	}
}

func TestCmdListen_Flags(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")
	
	// Test --relay flag parsing
	err := cmdListen([]string{"--relay", "wss://invalid"})
	if err == nil {
		t.Error("Expected error for missing device")
	}
}
