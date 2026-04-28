package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/gowebpki/jcs"
	"github.com/sigilauth/cli-device/internal/crypto"
)

// cmdCryptoSign dispatches to auth/mpa/decrypt subcommands per tests/cross-impl/EXAMPLE-CLI-HARNESS.md
func cmdCryptoSign(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sigil-device crypto-sign <auth|mpa|decrypt> [options]")
	}

	subcommand := args[0]
	subargs := args[1:]

	switch subcommand {
	case "auth":
		return cmdCryptoSignAuth(subargs)
	case "mpa":
		return cmdCryptoSignMPA(subargs)
	case "decrypt":
		return cmdCryptoSignDecrypt(subargs)
	case "custom":
		return cmdCryptoSignCustom(subargs)
	case "envelope-decrypt":
		return cmdEnvelopeDecrypt(subargs)
	case "--help", "-h":
		printCryptoSignHelp()
		return nil
	default:
		return fmt.Errorf("unknown subcommand: %s (expected: auth, mpa, decrypt, custom, envelope-decrypt)", subcommand)
	}
}

func printCryptoSignHelp() {
	fmt.Println("Usage: sigil-device crypto-sign <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  auth              Sign authentication challenge with action context")
	fmt.Println("  mpa               Sign MPA action context")
	fmt.Println("  decrypt           Sign decrypt envelope")
	fmt.Println("  custom            Sign with custom domain tag (for test vectors)")
	fmt.Println("  envelope-decrypt  Decrypt and verify ECIES envelope (test harness)")
	fmt.Println()
	fmt.Println("For subcommand-specific help:")
	fmt.Println("  sigil-device crypto-sign auth --help")
	fmt.Println("  sigil-device crypto-sign custom --help")
	fmt.Println("  sigil-device crypto-sign envelope-decrypt --help")
}

// cmdCryptoSignAuth implements AUTH domain signing per domain-separation.md
//
// Usage: crypto-sign auth --priv-hex <key> --challenge-hex <hex> --action-context-json <json>
//
// Algorithm:
// 1. Parse action_context JSON
// 2. Canonicalize JSON (RFC 8785)
// 3. action_hash = SHA256(canonical_json)
// 4. message = challenge_bytes || action_hash (64 bytes)
// 5. tagged = "SIGIL-AUTH-V1\x00" || message
// 6. signature = ECDSA-P256-Sign(priv_key, SHA256(tagged))
//
// Output: 128-character hex string (64-byte R||S signature)
func cmdCryptoSignAuth(args []string) error {
	var privKeyHex string
	var challengeHex string
	var actionContextJSON string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--priv-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--priv-hex requires a value")
			}
			privKeyHex = args[i+1]
			i++
		case "--challenge-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--challenge-hex requires a value")
			}
			challengeHex = args[i+1]
			i++
		case "--action-context-json":
			if i+1 >= len(args) {
				return fmt.Errorf("--action-context-json requires a value")
			}
			actionContextJSON = args[i+1]
			i++
		case "--help", "-h":
			fmt.Println("Usage: crypto-sign auth --priv-hex <key> --challenge-hex <hex> --action-context-json <json>")
			return nil
		}
	}

	if privKeyHex == "" || challengeHex == "" || actionContextJSON == "" {
		return fmt.Errorf("required: --priv-hex, --challenge-hex, --action-context-json")
	}

	// Parse private key
	privKey, err := parsePrivateKey(privKeyHex)
	if err != nil {
		return err
	}

	// Parse challenge
	challengeBytes, err := hex.DecodeString(challengeHex)
	if err != nil {
		return fmt.Errorf("invalid challenge hex: %w", err)
	}
	if len(challengeBytes) != 32 {
		return fmt.Errorf("challenge must be 32 bytes, got %d", len(challengeBytes))
	}

	// Parse and canonicalize action context
	var actionContext interface{}
	if err := json.Unmarshal([]byte(actionContextJSON), &actionContext); err != nil {
		return fmt.Errorf("invalid action context JSON: %w", err)
	}

	_, err = jcs.Transform([]byte(actionContextJSON))
	if err != nil {
		return fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	actionHash, err := crypto.ComputeActionContextHash(actionContext)
	if err != nil {
		return fmt.Errorf("failed to compute action hash: %w", err)
	}

	// Build message: challenge_bytes || action_hash (64 bytes)
	message := append(challengeBytes, actionHash...)

	// Sign with AUTH domain tag
	signature, err := crypto.SignWithDomain(privKey, crypto.DomainAuth, message)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// Output as hex
	fmt.Println(hex.EncodeToString(signature))
	return nil
}

// cmdCryptoSignMPA implements MPA domain signing per domain-separation.md
//
// Usage: crypto-sign mpa --priv-hex <key> --message-hex <hex>
//
// Algorithm:
// 1. tagged = "SIGIL-MPA-V1\x00" || message_bytes
// 2. signature = ECDSA-P256-Sign(priv_key, SHA256(tagged))
//
// Output: 128-character hex string (64-byte R||S signature)
func cmdCryptoSignMPA(args []string) error {
	var privKeyHex string
	var messageHex string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--priv-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--priv-hex requires a value")
			}
			privKeyHex = args[i+1]
			i++
		case "--message-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--message-hex requires a value")
			}
			messageHex = args[i+1]
			i++
		case "--help", "-h":
			fmt.Println("Usage: crypto-sign mpa --priv-hex <key> --message-hex <hex>")
			return nil
		}
	}

	if privKeyHex == "" || messageHex == "" {
		return fmt.Errorf("required: --priv-hex, --message-hex")
	}

	privKey, err := parsePrivateKey(privKeyHex)
	if err != nil {
		return err
	}

	messageBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		return fmt.Errorf("invalid message hex: %w", err)
	}

	signature, err := crypto.SignWithDomain(privKey, crypto.DomainMPA, messageBytes)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	fmt.Println(hex.EncodeToString(signature))
	return nil
}

// cmdCryptoSignDecrypt implements DECRYPT domain signing per domain-separation.md
//
// Usage: crypto-sign decrypt --priv-hex <key> --message-hex <hex>
//
// Algorithm:
// 1. tagged = "SIGIL-DECRYPT-V1\x00" || message_bytes
// 2. signature = ECDSA-P256-Sign(priv_key, SHA256(tagged))
//
// Output: 128-character hex string (64-byte R||S signature)
func cmdCryptoSignDecrypt(args []string) error {
	var privKeyHex string
	var messageHex string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--priv-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--priv-hex requires a value")
			}
			privKeyHex = args[i+1]
			i++
		case "--message-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--message-hex requires a value")
			}
			messageHex = args[i+1]
			i++
		case "--help", "-h":
			fmt.Println("Usage: crypto-sign decrypt --priv-hex <key> --message-hex <hex>")
			return nil
		}
	}

	if privKeyHex == "" || messageHex == "" {
		return fmt.Errorf("required: --priv-hex, --message-hex")
	}

	privKey, err := parsePrivateKey(privKeyHex)
	if err != nil {
		return err
	}

	messageBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		return fmt.Errorf("invalid message hex: %w", err)
	}

	signature, err := crypto.SignWithDomain(privKey, crypto.DomainDecrypt, messageBytes)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	fmt.Println(hex.EncodeToString(signature))
	return nil
}

// cmdCryptoSignCustom implements custom domain tag signing for test vector generation
//
// Usage: crypto-sign custom --priv-hex <key> --domain-tag <tag> --message-hex <hex>
//
// Algorithm:
// 1. tagged = domain_tag (with \x00 appended if not present) || message_bytes
// 2. signature = ECDSA-P256-Sign(priv_key, SHA256(tagged))
//
// Output: 128-character hex string (64-byte R||S signature)
func cmdCryptoSignCustom(args []string) error {
	var privKeyHex string
	var domainTag string
	var messageHex string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--priv-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--priv-hex requires a value")
			}
			privKeyHex = args[i+1]
			i++
		case "--domain-tag":
			if i+1 >= len(args) {
				return fmt.Errorf("--domain-tag requires a value")
			}
			domainTag = args[i+1]
			i++
		case "--message-hex":
			if i+1 >= len(args) {
				return fmt.Errorf("--message-hex requires a value")
			}
			messageHex = args[i+1]
			i++
		case "--help", "-h":
			fmt.Println("Usage: crypto-sign custom --priv-hex <key> --domain-tag <tag> --message-hex <hex>")
			fmt.Println()
			fmt.Println("Signs message with arbitrary domain tag for test vector generation.")
			fmt.Println("Domain tag should include \\x00 terminator if required (e.g., 'SIGIL-AUTH-V1\\x00').")
			return nil
		}
	}

	if privKeyHex == "" || domainTag == "" || messageHex == "" {
		return fmt.Errorf("required: --priv-hex, --domain-tag, --message-hex")
	}

	privKey, err := parsePrivateKey(privKeyHex)
	if err != nil {
		return err
	}

	messageBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		return fmt.Errorf("invalid message hex: %w", err)
	}

	// Convert domain tag to bytes (user can include \x00 in the string or it will be appended)
	domainBytes := []byte(domainTag)

	// Append null terminator if not present
	if len(domainBytes) == 0 || domainBytes[len(domainBytes)-1] != 0 {
		domainBytes = append(domainBytes, 0)
	}

	signature, err := crypto.SignWithDomain(privKey, domainBytes, messageBytes)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	fmt.Println(hex.EncodeToString(signature))
	return nil
}

// parsePrivateKey parses a 32-byte hex private key into an ECDSA private key
func parsePrivateKey(hexStr string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(keyBytes))
	}

	d := new(big.Int).SetBytes(keyBytes)
	curve := elliptic.P256()

	// Derive public key
	x, y := curve.ScalarBaseMult(keyBytes)

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}
