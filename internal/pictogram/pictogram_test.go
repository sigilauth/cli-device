package pictogram

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestDerive(t *testing.T) {
	tests := []struct {
		name              string
		fingerprintHex    string
		expectedPictogram []string
	}{
		{
			name:           "All zeros fingerprint",
			fingerprintHex: "0000000000000000000000000000000000000000000000000000000000000000",
			// Index 0 repeated 5 times = apple
			expectedPictogram: []string{"🍎", "🍎", "🍎", "🍎", "🍎"},
		},
		{
			name:           "All 0xFF fingerprint (max indices)",
			fingerprintHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			// Index 63 repeated 5 times = fire
			expectedPictogram: []string{"🔥", "🔥", "🔥", "🔥", "🔥"},
		},
		{
			name:           "Known fingerprint from test vectors",
			fingerprintHex: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			// Indices: [40, 27, 11, 3, 53] = tree, rocket, mushroom, orange, moai
			expectedPictogram: []string{"🌲", "🚀", "🍄", "🍊", "🗿"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fingerprintBytes, err := hex.DecodeString(tc.fingerprintHex)
			if err != nil {
				t.Fatalf("Failed to decode fingerprint hex: %v", err)
			}

			pictogram, err := Derive(fingerprintBytes)
			if err != nil {
				t.Fatalf("Derive() error = %v", err)
			}

			if !reflect.DeepEqual(pictogram, tc.expectedPictogram) {
				t.Errorf("Derive() pictogram = %v, want %v", pictogram, tc.expectedPictogram)
			}
		})
	}
}

func TestFromFingerprint(t *testing.T) {
	tests := []struct {
		name              string
		fingerprint       string
		expectedEmojis    []string
		expectedSpeakable string
	}{
		{
			name:              "All zeros",
			fingerprint:       "0000000000000000000000000000000000000000000000000000000000000000",
			expectedEmojis:    []string{"🍎", "🍎", "🍎", "🍎", "🍎"},
			expectedSpeakable: "apple apple apple apple apple",
		},
		{
			name:              "All 0xFF",
			fingerprint:       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expectedEmojis:    []string{"🔥", "🔥", "🔥", "🔥", "🔥"},
			expectedSpeakable: "fire fire fire fire fire",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			emojis, speakable := FromFingerprint(tc.fingerprint)

			if !reflect.DeepEqual(emojis, tc.expectedEmojis) {
				t.Errorf("FromFingerprint() emojis = %v, want %v", emojis, tc.expectedEmojis)
			}

			if speakable != tc.expectedSpeakable {
				t.Errorf("FromFingerprint() speakable = %q, want %q", speakable, tc.expectedSpeakable)
			}
		})
	}
}

func TestDerive_ErrorCases(t *testing.T) {
	tests := []struct {
		name             string
		fingerprintBytes []byte
		wantErr          bool
	}{
		{
			name:             "Empty fingerprint",
			fingerprintBytes: []byte{},
			wantErr:          true,
		},
		{
			name:             "Too short (3 bytes)",
			fingerprintBytes: []byte{0x01, 0x02, 0x03},
			wantErr:          true,
		},
		{
			name:             "Exactly 4 bytes (minimum valid)",
			fingerprintBytes: []byte{0x00, 0x00, 0x00, 0x00},
			wantErr:          false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Derive(tc.fingerprintBytes)
			if (err != nil) != tc.wantErr {
				t.Errorf("Derive() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestSpeakable(t *testing.T) {
	tests := []struct {
		name      string
		pictogram []string
		want      string
	}{
		{
			name:      "5-emoji pictogram",
			pictogram: []string{"🐶", "🐱", "🐭", "🐹", "🐰"},
			want:      "🐶 🐱 🐭 🐹 🐰",
		},
		{
			name:      "Empty pictogram",
			pictogram: []string{},
			want:      "",
		},
		{
			name:      "Single emoji",
			pictogram: []string{"🔥"},
			want:      "🔥",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Speakable(tc.pictogram)
			if got != tc.want {
				t.Errorf("Speakable() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCanonicalVectors validates pictogram derivation against canonical test vectors
// from api/test-vectors/pictogram.json. This ensures byte-for-byte compatibility
// with all other Sigil Auth implementations.
func TestCanonicalVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/pictogram.json")
	if err != nil {
		t.Fatalf("Failed to read test vectors: %v", err)
	}

	var testVectors struct {
		Vectors []struct {
			Name                        string   `json:"name"`
			FingerprintHex              string   `json:"fingerprint_hex"`
			Indices                     []int    `json:"indices"`
			ExpectedPictogram           []string `json:"expected_pictogram"`
			ExpectedPictogramSpeakable  string   `json:"expected_pictogram_speakable"`
		} `json:"vectors"`
	}

	if err := json.Unmarshal(data, &testVectors); err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}

	for _, tc := range testVectors.Vectors {
		t.Run(tc.Name, func(t *testing.T) {
			fingerprintBytes, err := hex.DecodeString(tc.FingerprintHex)
			if err != nil {
				t.Fatalf("Failed to decode fingerprint: %v", err)
			}

			// Test word-based output via FromFingerprint
			_, speakable := FromFingerprint(tc.FingerprintHex)
			if speakable != tc.ExpectedPictogramSpeakable {
				t.Errorf("FromFingerprint() speakable = %q, want %q", speakable, tc.ExpectedPictogramSpeakable)
			}

			// Verify indices are correctly extracted
			firstFourBytes := binary.BigEndian.Uint32(fingerprintBytes[:4])
			for i, expectedIdx := range tc.Indices {
				bitOffset := 26 - (i * 6)
				gotIdx := int((firstFourBytes >> bitOffset) & 0x3F)
				if gotIdx != expectedIdx {
					t.Errorf("Index[%d] = %d, want %d", i, gotIdx, expectedIdx)
				}
			}

			// Verify wordlist mapping
			for i, expectedWord := range tc.ExpectedPictogram {
				idx := tc.Indices[i]
				gotWord := Wordlist[idx]
				if gotWord != expectedWord {
					t.Errorf("Wordlist[%d] = %q, want %q", idx, gotWord, expectedWord)
				}
			}
		})
	}
}
