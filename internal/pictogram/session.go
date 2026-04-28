package pictogram

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
)

//go:embed testdata/pictogram-pool-v1.json
var poolFS embed.FS

// Pool192 is the 192-entry pictogram pool for session pictograms
var Pool192 []PoolEntry

// PoolEntry represents a single emoji-word pair from the pictogram pool
type PoolEntry struct {
	Index int    `json:"index"`
	Emoji string `json:"emoji"`
	Name  string `json:"name"`
}

// PoolData is the structure of pictogram-pool-v1.json
type PoolData struct {
	Version    int        `json:"version"`
	PoolSize   int        `json:"pool_size"`
	Categories []Category `json:"categories"`
}

// Category is a grouping of pictogram entries
type Category struct {
	Name    string      `json:"name"`
	Entries []PoolEntry `json:"entries"`
}

func init() {
	// Load pool from embedded JSON
	poolJSON, err := poolFS.ReadFile("testdata/pictogram-pool-v1.json")
	if err != nil {
		panic(fmt.Sprintf("failed to read pictogram pool: %v", err))
	}

	var poolData PoolData
	if err := json.Unmarshal(poolJSON, &poolData); err != nil {
		panic(fmt.Sprintf("failed to parse pictogram pool: %v", err))
	}

	if poolData.PoolSize != 192 {
		panic(fmt.Sprintf("invalid pool size: expected 192, got %d", poolData.PoolSize))
	}

	// Flatten categories into Pool192
	Pool192 = make([]PoolEntry, 192)
	idx := 0
	for _, cat := range poolData.Categories {
		for _, entry := range cat.Entries {
			if entry.Index != idx {
				panic(fmt.Sprintf("pool index mismatch: expected %d, got %d", idx, entry.Index))
			}
			Pool192[idx] = entry
			idx++
		}
	}

	if idx != 192 {
		panic(fmt.Sprintf("pool size mismatch: expected 192 entries, got %d", idx))
	}
}

// DeriveSessionPictogram computes session pictogram using Argon2id per wire-protocol.md §4.2
//
// Inputs:
//   - serverPub: 33-byte compressed P-256 public key
//   - clientPub: 33-byte compressed P-256 public key
//   - serverNonce: 32-byte cryptographic random nonce
//
// Algorithm:
//  1. password = SHA-256(serverPub || clientPub || serverNonce)
//  2. salt = "SIGIL-PAIR-V1\x00\x00\x00" (16 bytes, domain-separated, zero-padded)
//  3. derived = Argon2id(password, salt, m=65536, t=10, p=1, dkLen=32)
//  4. Extract 6 indices: each is 16 bits big-endian, modulo 192
//  5. Map to emoji-word pairs from Pool192
//
// Returns 6 emoji-word pairs ([]string emojis, []string words)
func DeriveSessionPictogram(serverPub, clientPub, serverNonce []byte) ([]string, []string, error) {
	if len(serverPub) != 33 {
		return nil, nil, fmt.Errorf("serverPub must be 33 bytes, got %d", len(serverPub))
	}
	if len(clientPub) != 33 {
		return nil, nil, fmt.Errorf("clientPub must be 33 bytes, got %d", len(clientPub))
	}
	if len(serverNonce) != 32 {
		return nil, nil, fmt.Errorf("serverNonce must be 32 bytes, got %d", len(serverNonce))
	}

	// Step 1: password = SHA-256(serverPub || clientPub || serverNonce)
	hasher := sha256.New()
	hasher.Write(serverPub)
	hasher.Write(clientPub)
	hasher.Write(serverNonce)
	password := hasher.Sum(nil) // 32 bytes

	// Step 2: salt = "SIGIL-PAIR-V1\x00\x00\x00" (16 bytes)
	salt := []byte("SIGIL-PAIR-V1\x00\x00\x00")

	// Step 3: Argon2id key derivation
	// Parameters per spec: m=65536 (64 MiB), t=10, p=1, dkLen=32
	derived := argon2.IDKey(password, salt, 10, 65536, 1, 32)

	// Step 4: Extract 6 indices from derived key
	// Each index is 16 bits big-endian, modulo 192
	emojis := make([]string, 6)
	words := make([]string, 6)

	for i := 0; i < 6; i++ {
		// Read 2 bytes as big-endian uint16
		byteIdx := i * 2
		wordIndex := (uint16(derived[byteIdx]) << 8) | uint16(derived[byteIdx+1])
		poolIdx := int(wordIndex) % 192

		emojis[i] = Pool192[poolIdx].Emoji
		words[i] = Pool192[poolIdx].Name
	}

	return emojis, words, nil
}

// FormatSessionPictogram formats emojis and words for display
// Example: "🍎 apple    🚀 rocket    🦊 fox    ⚓ anchor    🌙 moon    🏠 house"
func FormatSessionPictogram(emojis, words []string) string {
	if len(emojis) != 6 || len(words) != 6 {
		return ""
	}

	result := ""
	for i := 0; i < 6; i++ {
		if i > 0 {
			result += "    "
		}
		result += fmt.Sprintf("%s %s", emojis[i], words[i])
	}
	return result
}

// SpeakableSessionPictogram returns space-separated words only
// Example: "apple rocket fox anchor moon house"
func SpeakableSessionPictogram(words []string) string {
	if len(words) != 6 {
		return ""
	}

	result := ""
	for i, word := range words {
		if i > 0 {
			result += " "
		}
		result += word
	}
	return result
}
