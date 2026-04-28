package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// TestAuthV1DomainSeparation validates domain-separated signatures match test vectors
func TestAuthV1DomainSeparation(t *testing.T) {
	data, err := os.ReadFile("testdata/domain-separation/auth-v1.json")
	if err != nil {
		t.Fatalf("Failed to read auth-v1.json: %v", err)
	}

	var vectors struct {
		Vectors []struct {
			Name                      string                 `json:"name"`
			PrivateKeyHex             string                 `json:"private_key_hex"`
			DomainTag                 string                 `json:"domain_tag"`
			ChallengeBytesHex         string                 `json:"challenge_bytes_hex"`
			ActionContextJSON         map[string]interface{} `json:"action_context_json"`
			ActionContextCanonical    string                 `json:"action_context_canonical"`
			ActionContextHashHex      string                 `json:"action_context_hash_hex"`
			ExpectedSignatureHex      string                 `json:"expected_signature_hex"`
		} `json:"vectors"`
	}

	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse auth-v1.json: %v", err)
	}

	for _, tc := range vectors.Vectors {
		t.Run(tc.Name, func(t *testing.T) {
			// Decode private key
			keyBytes, err := hex.DecodeString(tc.PrivateKeyHex)
			if err != nil {
				t.Fatalf("Failed to decode private key: %v", err)
			}
			d := new(big.Int).SetBytes(keyBytes)
			privateKey := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
				D: d,
			}
			privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.Curve.ScalarBaseMult(d.Bytes())

			// Compute action context hash
			var actionCtx interface{}
			if tc.ActionContextJSON != nil {
				actionCtx = tc.ActionContextJSON
			}
			actionHash, err := ComputeActionContextHash(actionCtx)
			if err != nil {
				t.Fatalf("Failed to compute action context hash: %v", err)
			}

			// Verify action hash matches expected
			if hex.EncodeToString(actionHash) != tc.ActionContextHashHex {
				t.Errorf("Action hash mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(actionHash), tc.ActionContextHashHex)
			}

			// Build message: challenge_bytes || action_hash
			challengeBytes, _ := hex.DecodeString(tc.ChallengeBytesHex)
			message := append(challengeBytes, actionHash...)

			// Sign with domain separation
			// Note: Go crypto/ecdsa uses randomized ECDSA, not RFC 6979 deterministic.
			// We verify the signature is valid, but can't match exact bytes.
			signature, err := SignWithDomain(privateKey, DomainAuth, message)
			if err != nil {
				t.Fatalf("SignWithDomain failed: %v", err)
			}

			// Verify our signature is valid
			taggedInput := append(DomainAuth, message...)
			err = Verify(&privateKey.PublicKey, taggedInput, signature)
			if err != nil {
				t.Errorf("Signature verification failed: %v", err)
			}

			// Verify test vector's expected signature (RFC 6979 deterministic)
			// This validates the test vectors are correct, even though we don't produce them
			expectedSig, _ := hex.DecodeString(tc.ExpectedSignatureHex)
			err = Verify(&privateKey.PublicKey, taggedInput, expectedSig)
			if err != nil {
				t.Errorf("Test vector signature verification failed: %v", err)
			}
		})
	}
}

// TestEmptyActionContextHash validates SHA256('{}') matches fixed constant
func TestEmptyActionContextHash(t *testing.T) {
	hash, err := ComputeActionContextHash(nil)
	if err != nil {
		t.Fatalf("Failed to compute empty action context hash: %v", err)
	}

	// From auth-v1.json empty_action_context_hash.sha256_hex
	expected := "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	got := hex.EncodeToString(hash)
	if got != expected {
		t.Errorf("Empty action context hash mismatch:\n  got:  %s\n  want: %s", got, expected)
	}
}

// TestCrossDomainRejection validates signatures from one domain don't verify under another
func TestCrossDomainRejection(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("test message")

	// Sign with DomainAuth
	authSig, err := SignWithDomain(privateKey, DomainAuth, message)
	if err != nil {
		t.Fatalf("SignWithDomain(DomainAuth) failed: %v", err)
	}

	// Verify under DomainAuth — should succeed
	authTagged := append(DomainAuth, message...)
	err = Verify(&privateKey.PublicKey, authTagged, authSig)
	if err != nil {
		t.Errorf("Verification under DomainAuth should succeed, got: %v", err)
	}

	// Verify under DomainMPA — MUST FAIL
	mpaTagged := append(DomainMPA, message...)
	err = Verify(&privateKey.PublicKey, mpaTagged, authSig)
	if err == nil {
		t.Error("Verification under DomainMPA should fail for DomainAuth signature")
	}

	// Verify under DomainDecrypt — MUST FAIL
	decryptTagged := append(DomainDecrypt, message...)
	err = Verify(&privateKey.PublicKey, decryptTagged, authSig)
	if err == nil {
		t.Error("Verification under DomainDecrypt should fail for DomainAuth signature")
	}
}
