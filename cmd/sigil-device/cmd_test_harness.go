package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/sigilauth/cli-device/internal/crypto"
	"github.com/sigilauth/cli-device/internal/envelope"
	"github.com/sigilauth/cli-device/internal/pictogram"
	"golang.org/x/crypto/hkdf"
)

// cmdPairHandshake derives session pictogram from server pubkey + client pubkey + server nonce
// Per tests/cross-impl/EXAMPLE-CLI-HARNESS.md lines 820-849
//
// Usage: sigil-device pair-handshake --server-pub-hex <hex> --client-pub-hex <hex> --server-nonce-hex <hex>
//
// Output: 6 space-separated pictogram words, no trailing newline
// Exit: 0 (success), 1 (validation error), 2 (crypto error)
func cmdPairHandshake(args []string) error {
	var serverPubHex string
	var clientPubHex string
	var serverNonceHex string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server-pub-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--server-pub-hex requires a value")
			}
			serverPubHex = args[i+1]
			i++
		case "--client-pub-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--client-pub-hex requires a value")
			}
			clientPubHex = args[i+1]
			i++
		case "--server-nonce-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--server-nonce-hex requires a value")
			}
			serverNonceHex = args[i+1]
			i++
		case "--help", "-h":
			fmt.Fprintln(os.Stderr, "Usage: pair-handshake --server-pub-hex <hex> --client-pub-hex <hex> --server-nonce-hex <hex>")
			os.Exit(0)
		}
	}

	if serverPubHex == "" || clientPubHex == "" || serverNonceHex == "" {
		fmt.Fprintln(os.Stderr, "missing required arguments")
		os.Exit(1)
	}

	// Validate and decode server public key (33 bytes = 66 hex chars)
	serverPubBytes, err := hex.DecodeString(serverPubHex)
	if err != nil || len(serverPubBytes) != 33 {
		fmt.Fprintln(os.Stderr, "invalid server public key")
		os.Exit(1)
	}

	// Validate and decode client public key (33 bytes = 66 hex chars)
	clientPubBytes, err := hex.DecodeString(clientPubHex)
	if err != nil || len(clientPubBytes) != 33 {
		fmt.Fprintln(os.Stderr, "invalid client public key")
		os.Exit(1)
	}

	// Validate and decode server nonce (32 bytes = 64 hex chars)
	serverNonceBytes, err := hex.DecodeString(serverNonceHex)
	if err != nil || len(serverNonceBytes) != 32 {
		fmt.Fprintln(os.Stderr, "invalid server nonce")
		os.Exit(1)
	}

	// Derive session pictogram
	_, words, err := pictogram.DeriveSessionPictogram(serverPubBytes, clientPubBytes, serverNonceBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "argon2id derivation failed")
		os.Exit(2)
	}

	// Output: 6 space-separated words, no trailing newline
	fmt.Print(strings.Join(words, " "))
	return nil
}

// cmdEnvelopeEncrypt creates a sign-then-encrypt envelope
// Per tests/cross-impl/EXAMPLE-CLI-HARNESS.md lines 851-878
//
// Usage: sigil-device envelope-encrypt --sender-priv-hex <hex> --recipient-pub-hex <hex> --payload-json <json>
//
// Output: base64-encoded envelope, no trailing newline
// Exit: 0 (success), 1 (validation error), 2 (crypto error)
func cmdEnvelopeEncrypt(args []string) error {
	var senderPrivHex string
	var recipientPubHex string
	var payloadJSON string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--sender-priv-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--sender-priv-hex requires a value")
			}
			senderPrivHex = args[i+1]
			i++
		case "--recipient-pub-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--recipient-pub-hex requires a value")
			}
			recipientPubHex = args[i+1]
			i++
		case "--payload-json":
			if i+1 >= len(args) {
				return fmt.Errorf("--payload-json requires a value")
			}
			payloadJSON = args[i+1]
			i++
		case "--help", "-h":
			fmt.Fprintln(os.Stderr, "Usage: envelope-encrypt --sender-priv-hex <hex> --recipient-pub-hex <hex> --payload-json <json>")
			os.Exit(0)
		}
	}

	if senderPrivHex == "" || recipientPubHex == "" || payloadJSON == "" {
		fmt.Fprintln(os.Stderr, "missing required arguments")
		os.Exit(1)
	}

	// Validate and decode sender private key (32 bytes = 64 hex chars)
	senderPrivBytes, err := hex.DecodeString(senderPrivHex)
	if err != nil || len(senderPrivBytes) != 32 {
		fmt.Fprintln(os.Stderr, "invalid sender private key")
		os.Exit(1)
	}

	// Validate and decode recipient public key (33 bytes = 66 hex chars)
	recipientPubBytes, err := hex.DecodeString(recipientPubHex)
	if err != nil || len(recipientPubBytes) != 33 {
		fmt.Fprintln(os.Stderr, "invalid recipient public key")
		os.Exit(1)
	}

	// Validate payload JSON
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		fmt.Fprintln(os.Stderr, "invalid JSON payload")
		os.Exit(1)
	}

	// Build sender private key
	d := new(big.Int).SetBytes(senderPrivBytes)
	curve := elliptic.P256()
	senderPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     nil,
			Y:     nil,
		},
		D: d,
	}
	senderPrivKey.PublicKey.X, senderPrivKey.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	// Decompress recipient public key
	recipientPubKey, err := crypto.DecompressPublicKey(recipientPubBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to decompress recipient public key")
		os.Exit(2)
	}

	// For test harness, use fixed nonce and action from payload if present
	action, _ := payload["action"].(string)
	if action == "" {
		action = "test.action"
	}

	// Generate nonce
	nonce, err := envelope.GenerateNonce()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to generate nonce")
		os.Exit(2)
	}

	// Create envelope
	envelopeB64, err := envelope.CreateRequest(senderPrivKey, recipientPubKey, action, payload, nonce)
	if err != nil {
		fmt.Fprintln(os.Stderr, "envelope creation failed")
		os.Exit(2)
	}

	// Output: base64 string, no trailing newline
	fmt.Print(envelopeB64)
	return nil
}

// cmdEnvelopeDecrypt decrypts and verifies an envelope
// Per tests/cross-impl/EXAMPLE-CLI-HARNESS.md lines 880-929
//
// Usage: sigil-device envelope-decrypt --recipient-priv-hex <hex> --envelope-base64 <base64>
//
// Output: canonical JSON payload, no trailing newline
// Exit: 0 (success), 2 (all errors)
// Errors on stderr: ENVELOPE_INVALID, INVALID_SIGNATURE, MALFORMED_PAYLOAD, MALFORMED_ENVELOPE
func cmdEnvelopeDecrypt(args []string) error {
	var recipientPrivHex string
	var envelopeB64 string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--recipient-priv-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--recipient-priv-hex requires a value")
			}
			recipientPrivHex = args[i+1]
			i++
		case "--envelope-base64":
			if i+1 >= len(args) {
				return fmt.Errorf("--envelope-base64 requires a value")
			}
			envelopeB64 = args[i+1]
			i++
		case "--help", "-h":
			fmt.Fprintln(os.Stderr, "Usage: envelope-decrypt --recipient-priv-hex <hex> --envelope-base64 <base64>")
			os.Exit(0)
		}
	}

	if recipientPrivHex == "" || envelopeB64 == "" {
		fmt.Fprintln(os.Stderr, "missing required arguments")
		os.Exit(1)
	}

	// Validate and decode recipient private key (32 bytes = 64 hex chars)
	recipientPrivBytes, err := hex.DecodeString(recipientPrivHex)
	if err != nil || len(recipientPrivBytes) != 32 {
		fmt.Fprintln(os.Stderr, "invalid recipient private key")
		os.Exit(1)
	}

	// Build recipient private key
	d := new(big.Int).SetBytes(recipientPrivBytes)
	curve := elliptic.P256()
	recipientPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     nil,
			Y:     nil,
		},
		D: d,
	}
	recipientPrivKey.PublicKey.X, recipientPrivKey.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	// Decode base64 envelope
	outerCiphertext, err := base64.StdEncoding.DecodeString(envelopeB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Validate minimum length
	if len(outerCiphertext) < 33+12+16 {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Decrypt ECIES outer layer
	innerJSON, err := decryptECIES(recipientPrivKey, outerCiphertext)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Parse inner envelope structure
	var innerEnvelope struct {
		ClientPublicKey string `json:"client_public_key"`
		Payload         string `json:"payload"`
		Signature       string `json:"signature"`
	}

	if err := json.Unmarshal(innerJSON, &innerEnvelope); err != nil {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	// Verify required fields
	if innerEnvelope.ClientPublicKey == "" || innerEnvelope.Payload == "" || innerEnvelope.Signature == "" {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	// Decode sender public key
	senderPubKeyBytes, err := base64.StdEncoding.DecodeString(innerEnvelope.ClientPublicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	senderPubKey, err := crypto.DecompressPublicKey(senderPubKeyBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(innerEnvelope.Signature)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	// Parse payload and validate required fields (ADV-07 protection)
	var payload struct {
		Action    string                 `json:"action"`
		Nonce     string                 `json:"nonce"`
		Timestamp int64                  `json:"timestamp"`
		Audience  string                 `json:"audience"`
		Body      map[string]interface{} `json:"body"`
	}
	if err := json.Unmarshal([]byte(innerEnvelope.Payload), &payload); err != nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Validate all required fields present (ADV-07 protection)
	if payload.Action == "" || payload.Nonce == "" || payload.Timestamp == 0 || payload.Audience == "" || payload.Body == nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Re-canonicalize payload before signature verification (ADV-10 protection)
	payloadCanonical, err := jsoncanonicalizer.Transform([]byte(innerEnvelope.Payload))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Verify signature with SIGIL-CONV-V1 domain tag against canonical payload
	domainTag := []byte("SIGIL-CONV-V1\x00")
	signedBytes := append(domainTag, payloadCanonical...)
	if err := crypto.Verify(senderPubKey, signedBytes, signature); err != nil {
		fmt.Fprintln(os.Stderr, "INVALID_SIGNATURE")
		os.Exit(2)
	}

	// Output: canonical JSON payload, no trailing newline
	fmt.Print(string(payloadCanonical))
	return nil
}

// decryptECIES decrypts ECIES ciphertext (helper for test harness)
func decryptECIES(recipientPrivKey *ecdsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	// This is a simplified version of the envelope ECIES decryption
	// Wire format: ephemeral_public (33) || nonce (12) || ciphertext || tag (16)

	minLen := 33 + 12 + 16
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("ciphertext too short")
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

	// Derive encryption key using HKDF
	recipientCompressed := crypto.CompressPublicKey(&recipientPrivKey.PublicKey)
	fingerprint := sha256.Sum256(recipientCompressed)

	// DEBUG: Print all crypto parameters for Windows comparison
	if os.Getenv("DEBUG_ECIES") == "1" {
		fmt.Fprintf(os.Stderr, "DEBUG ephemeral_pub: %x\n", ephemeralCompressed)
		fmt.Fprintf(os.Stderr, "DEBUG recipient_pub: %x\n", recipientCompressed)
		fmt.Fprintf(os.Stderr, "DEBUG shared_secret: %x\n", sharedX.Bytes())
		fmt.Fprintf(os.Stderr, "DEBUG recipient_fingerprint (salt): %x\n", fingerprint[:])
	}

	hkdfReader := hkdf.New(sha256.New, sharedX.Bytes(), fingerprint[:], []byte("SIGIL-CONV-V1-AES256"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// DEBUG: Print derived AES key
	if os.Getenv("DEBUG_ECIES") == "1" {
		fmt.Fprintf(os.Stderr, "DEBUG aes_key: %x\n", aesKey)
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

	// AAD = ephemeral_public per spec §2.3 (SIGIL-CONV-V1)
	// CRITICAL: Must match server commit c2116d0
	aad := ephemeralCompressed

	// DEBUG: Print GCM parameters
	if os.Getenv("DEBUG_ECIES") == "1" {
		fmt.Fprintf(os.Stderr, "DEBUG aad: %x\n", aad)
		fmt.Fprintf(os.Stderr, "DEBUG nonce: %x\n", nonce)
		fmt.Fprintf(os.Stderr, "DEBUG ciphertext_len: %d\n", len(ciphertextAndTag)-16)
		if len(ciphertextAndTag) >= 16 {
			fmt.Fprintf(os.Stderr, "DEBUG tag: %x\n", ciphertextAndTag[len(ciphertextAndTag)-16:])
		}
	}

	// Decrypt with AAD = ephemeral_public
	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
