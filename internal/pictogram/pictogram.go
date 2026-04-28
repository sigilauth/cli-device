package pictogram

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Wordlist is the canonical 64-word pictogram list per api/pictogram-wordlist.md
// MUST NOT be reordered — any change requires a coordinated protocol version bump
// across all 7 implementations (server, relay, cli-device, iOS, Android, macOS, Windows, Linux).
//
// Word selection criteria (per protocol spec):
// - Short (1-2 syllables preferred)
// - Globally recognizable (food, animals, vehicles, nature, objects)
// - Unambiguous (no homophones or easily confused words)
// - Family-friendly
var Wordlist = [64]string{
	// 0-7: Fruits
	"apple", "banana", "grapes", "orange", "lemon", "cherry", "strawberry", "kiwi",

	// 8-15: Vegetables
	"carrot", "corn", "broccoli", "mushroom", "pepper", "avocado", "onion", "peanut",

	// 16-23: Food
	"pizza", "burger", "taco", "donut", "cookie", "cake", "cupcake", "popcorn",

	// 24-31: Vehicles
	"car", "taxi", "bus", "rocket", "plane", "helicopter", "sailboat", "bicycle",

	// 32-39: Animals
	"dog", "cat", "fish", "butterfly", "bee", "fox", "lion", "elephant",

	// 40-47: Nature
	"tree", "sunflower", "cactus", "clover", "blossom", "rainbow", "star", "moon",

	// 48-55: Places
	"house", "mountain", "peak", "volcano", "island", "moai", "tent", "castle",

	// 56-63: Objects
	"key", "bell", "books", "guitar", "anchor", "crown", "diamond", "fire",
}

// EmojiList maps each word to its corresponding emoji character.
// This is optional visual enhancement; the canonical representation is the word itself.
var EmojiList = [64]string{
	// 0-7: Fruits
	"🍎", "🍌", "🍇", "🍊", "🍋", "🍒", "🍓", "🥝",

	// 8-15: Vegetables
	"🥕", "🌽", "🥦", "🍄", "🌶️", "🥑", "🧅", "🥜",

	// 16-23: Food
	"🍕", "🍔", "🌮", "🍩", "🍪", "🍰", "🧁", "🍿",

	// 24-31: Vehicles
	"🚗", "🚕", "🚌", "🚀", "✈️", "🚁", "⛵", "🚲",

	// 32-39: Animals
	"🐶", "🐱", "🐟", "🦋", "🐝", "🦊", "🦁", "🐘",

	// 40-47: Nature
	"🌲", "🌻", "🌵", "🍀", "🌸", "🌈", "⭐", "🌙",

	// 48-55: Places
	"🏠", "⛰️", "🗻", "🌋", "🏝️", "🗿", "⛺", "🏰",

	// 56-63: Objects
	"🔑", "🔔", "📚", "🎸", "⚓", "👑", "💎", "🔥",
}

// NameList is deprecated. Use Wordlist instead.
// Kept for backward compatibility during migration.
var NameList = Wordlist

// FromFingerprint derives a pictogram from a hex-encoded fingerprint string
func FromFingerprint(fingerprint string) ([]string, string) {
	fingerprintBytes, err := hex.DecodeString(fingerprint)
	if err != nil || len(fingerprintBytes) < 4 {
		// Fallback to empty on error (should never happen with valid fingerprint)
		return []string{}, ""
	}

	// Read first 4 bytes as big-endian uint32
	firstFourBytes := binary.BigEndian.Uint32(fingerprintBytes[:4])

	// Extract 5 × 6-bit indices from the first 30 bits
	indices := [5]int{
		int((firstFourBytes >> 26) & 0x3F), // bits 0-5
		int((firstFourBytes >> 20) & 0x3F), // bits 6-11
		int((firstFourBytes >> 14) & 0x3F), // bits 12-17
		int((firstFourBytes >> 8) & 0x3F),  // bits 18-23
		int((firstFourBytes >> 2) & 0x3F),  // bits 24-29
	}

	emojis := make([]string, 5)
	names := make([]string, 5)
	for i, idx := range indices {
		emojis[i] = EmojiList[idx]
		names[i] = NameList[idx]
	}

	speakable := strings.Join(names, " ")
	return emojis, speakable
}

// Derive computes a 5-emoji pictogram from raw fingerprint bytes
func Derive(fingerprintBytes []byte) ([]string, error) {
	if len(fingerprintBytes) < 4 {
		return nil, fmt.Errorf("fingerprint too short: need at least 4 bytes, got %d", len(fingerprintBytes))
	}

	// Read first 4 bytes as big-endian uint32
	firstFourBytes := binary.BigEndian.Uint32(fingerprintBytes[:4])

	// Extract 5 × 6-bit indices from the first 30 bits
	indices := [5]int{
		int((firstFourBytes >> 26) & 0x3F), // bits 0-5
		int((firstFourBytes >> 20) & 0x3F), // bits 6-11
		int((firstFourBytes >> 14) & 0x3F), // bits 12-17
		int((firstFourBytes >> 8) & 0x3F),  // bits 18-23
		int((firstFourBytes >> 2) & 0x3F),  // bits 24-29
	}

	pictogram := make([]string, 5)
	for i, idx := range indices {
		pictogram[i] = EmojiList[idx]
	}

	return pictogram, nil
}

// Speakable joins a pictogram array into a space-separated string
func Speakable(pictogram []string) string {
	if len(pictogram) == 0 {
		return ""
	}

	result := pictogram[0]
	for i := 1; i < len(pictogram); i++ {
		result += " " + pictogram[i]
	}
	return result
}
