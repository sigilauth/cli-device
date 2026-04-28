package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/sigilauth/cli-device/internal/crypto"
	"golang.org/x/crypto/hkdf"
)

const (
	// Domain tag for SIGIL-CONV-V1 envelope signatures (16 bytes including NUL)
	domainConvV1 = "SIGIL-CONV-V1\x00"

	// ECIES info string for SIGIL-CONV-V1 envelope encryption
	eciesInfo = "SIGIL-CONV-V1-AES256"
)

// RequestPayload is the inner payload structure for requests
type RequestPayload struct {
	Action    string                 `json:"action"`
	Body      map[string]interface{} `json:"body"`
	Timestamp int64                  `json:"timestamp"`
	Nonce     string                 `json:"nonce"`
	Audience  string                 `json:"audience"`
}

// ResponsePayload is the inner payload structure for responses
type ResponsePayload struct {
	Status    string                 `json:"status"`
	Body      map[string]interface{} `json:"body,omitempty"`
	Timestamp int64                  `json:"timestamp"`
	Nonce     string                 `json:"nonce"`
}

// InnerEnvelope is the structure after signing, before outer encryption
type InnerEnvelope struct {
	ClientPublicKey string `json:"client_public_key"` // base64 compressed pubkey
	Payload         string `json:"payload"`            // canonical JSON string
	Signature       string `json:"signature"`          // base64 64-byte R||S
}

// CreateRequest creates a sign-then-encrypt envelope for a client request
//
// Steps per wire-protocol.md §5.1:
// 1. Canonicalize payload (RFC 8785)
// 2. Sign with domain tag SIGIL-CONV-V1
// 3. Build inner envelope
// 4. Encrypt to server public key
//
// Returns base64-encoded outer ciphertext
func CreateRequest(
	devicePrivKey *ecdsa.PrivateKey,
	serverPubKey *ecdsa.PublicKey,
	action string,
	body map[string]interface{},
	nonce string,
) (string, error) {
	// Build payload
	payload := RequestPayload{
		Action:    action,
		Body:      body,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
		Audience:  audienceFromPublicKey(serverPubKey),
	}

	// Canonicalize payload per RFC 8785
	canonicalJSON, err := canonicalize(payload)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize payload: %w", err)
	}

	// Sign with domain tag
	signedBytes := append([]byte(domainConvV1), canonicalJSON...)
	signature, err := crypto.Sign(devicePrivKey, signedBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Build inner envelope
	compressedPubKey := crypto.CompressPublicKey(&devicePrivKey.PublicKey)
	inner := InnerEnvelope{
		ClientPublicKey: base64.StdEncoding.EncodeToString(compressedPubKey),
		Payload:         string(canonicalJSON),
		Signature:       base64.StdEncoding.EncodeToString(signature),
	}

	// Canonicalize inner envelope
	innerJSON, err := canonicalize(inner)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize inner envelope: %w", err)
	}

	// Encrypt to server public key (ECIES)
	outerCiphertext, err := eciesEncrypt(serverPubKey, innerJSON)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt envelope: %w", err)
	}

	return base64.StdEncoding.EncodeToString(outerCiphertext), nil
}

// VerifyResponse decrypts and verifies a server response envelope
//
// Steps per wire-protocol.md §5.4:
// 1. Decrypt outer envelope with device private key
// 2. Parse inner envelope
// 3. Verify server signature
// 4. Verify timestamp freshness (300s window)
// 5. Return payload
func VerifyResponse(
	devicePrivKey *ecdsa.PrivateKey,
	serverPubKey *ecdsa.PublicKey,
	envelopeB64 string,
	nonceStore map[string]bool,
) (*ResponsePayload, error) {
	// Decode base64 outer ciphertext
	outerCiphertext, err := base64.StdEncoding.DecodeString(envelopeB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode envelope: %w", err)
	}

	// Decrypt outer envelope
	innerJSON, err := eciesDecrypt(devicePrivKey, outerCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt envelope: %w", err)
	}

	// Parse inner envelope
	var inner InnerEnvelope
	if err := json.Unmarshal(innerJSON, &inner); err != nil {
		return nil, fmt.Errorf("failed to parse inner envelope: %w", err)
	}

	// Decode server public key from inner envelope
	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(inner.ClientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server public key: %w", err)
	}

	receivedServerPubKey, err := crypto.DecompressPublicKey(serverPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress server public key: %w", err)
	}

	// Verify server public key matches expected
	expectedCompressed := crypto.CompressPublicKey(serverPubKey)
	if base64.StdEncoding.EncodeToString(expectedCompressed) != inner.ClientPublicKey {
		return nil, fmt.Errorf("server public key mismatch")
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(inner.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify signature with domain tag
	signedBytes := append([]byte(domainConvV1), []byte(inner.Payload)...)
	if err := crypto.Verify(receivedServerPubKey, signedBytes, signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Parse payload
	var payload ResponsePayload
	if err := json.Unmarshal([]byte(inner.Payload), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	// Verify timestamp freshness (300s window per spec §6.1)
	now := time.Now().Unix()
	if absInt64(now-payload.Timestamp) > 300 {
		return nil, fmt.Errorf("timestamp expired: %d seconds old", absInt64(now-payload.Timestamp))
	}

	// Verify nonce uniqueness (client MUST track response nonces per spec §5.4)
	if nonceStore != nil {
		if nonceStore[payload.Nonce] {
			return nil, fmt.Errorf("nonce reused: %s", payload.Nonce)
		}
		nonceStore[payload.Nonce] = true
	}

	return &payload, nil
}

// audienceFromPublicKey computes SHA256(compressed_pubkey) in hex
func audienceFromPublicKey(pubKey *ecdsa.PublicKey) string {
	compressed := crypto.CompressPublicKey(pubKey)
	hash := sha256.Sum256(compressed)
	return fmt.Sprintf("%x", hash[:])
}

// canonicalize serializes a struct to RFC 8785 canonical JSON
func canonicalize(v interface{}) ([]byte, error) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal failed: %w", err)
	}

	canonical, err := jcs.Transform(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("canonicalization failed: %w", err)
	}

	return canonical, nil
}

// eciesEncrypt encrypts plaintext to recipient public key using ECIES
//
// Wire format per spec §2.3:
// ephemeral_public (33 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
//
// Key derivation uses HKDF with info="SIGIL-CONV-V1-AES256"
func eciesEncrypt(recipientPubKey *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	// Generate ephemeral keypair
	ephemeralPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// ECDH: shared_secret = ephemeral_priv * recipient_pub
	sharedX, _ := recipientPubKey.Curve.ScalarMult(
		recipientPubKey.X,
		recipientPubKey.Y,
		ephemeralPrivKey.D.Bytes(),
	)

	// Compute fingerprint of recipient pubkey (used as salt per spec §2.3)
	recipientCompressed := crypto.CompressPublicKey(recipientPubKey)
	fingerprint := sha256.Sum256(recipientCompressed)

	// Derive encryption key: HKDF-SHA256(shared_secret, salt=fingerprint, info="SIGIL-CONV-V1-AES256")
	hkdfReader := hkdf.New(sha256.New, sharedX.Bytes(), fingerprint[:], []byte(eciesInfo))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with AAD = ephemeral_public (per spec §2.3)
	ephemeralCompressed := crypto.CompressPublicKey(&ephemeralPrivKey.PublicKey)
	ciphertextAndTag := gcm.Seal(nil, nonce, plaintext, ephemeralCompressed)

	// Build wire format: ephemeral_public || nonce || ciphertext || tag
	result := make([]byte, 0, 33+12+len(ciphertextAndTag))
	result = append(result, ephemeralCompressed...)
	result = append(result, nonce...)
	result = append(result, ciphertextAndTag...)

	return result, nil
}

// eciesDecrypt decrypts ECIES ciphertext using recipient private key
func eciesDecrypt(recipientPrivKey *ecdsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	minLen := 33 + 12 + 16
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", minLen, len(ciphertext))
	}

	// Extract components
	ephemeralCompressed := ciphertext[0:33]
	nonce := ciphertext[33:45]
	ciphertextAndTag := ciphertext[45:]

	// Decompress ephemeral public key
	ephemeralPubKey, err := crypto.DecompressPublicKey(ephemeralCompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress ephemeral public key: %w", err)
	}

	// ECDH: shared_secret = recipient_priv * ephemeral_pub
	sharedX, _ := ephemeralPubKey.Curve.ScalarMult(
		ephemeralPubKey.X,
		ephemeralPubKey.Y,
		recipientPrivKey.D.Bytes(),
	)

	// Compute fingerprint of recipient pubkey (used as salt)
	recipientCompressed := crypto.CompressPublicKey(&recipientPrivKey.PublicKey)
	fingerprint := sha256.Sum256(recipientCompressed)

	// Derive encryption key
	hkdfReader := hkdf.New(sha256.New, sharedX.Bytes(), fingerprint[:], []byte(eciesInfo))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt with AAD = ephemeral_public
	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, ephemeralCompressed)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// absInt64 returns absolute value of int64
func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// GenerateNonce generates a cryptographically random 16-byte nonce (hex-encoded to 32 chars)
func GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return fmt.Sprintf("%x", nonceBytes), nil
}
