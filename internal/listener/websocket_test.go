package listener

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sigilauth/cli-device/internal/crypto"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Test auth success flow
func TestClient_Connect_AuthSuccess(t *testing.T) {
	// Generate test keypair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create mock relay server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		// Send auth challenge
		challenge := make([]byte, 32)
		rand.Read(challenge)
		authChallenge := map[string]string{
			"type":       "auth_challenge",
			"challenge":  base64.StdEncoding.EncodeToString(challenge),
			"expires_at": time.Now().Add(30 * time.Second).Format(time.RFC3339),
		}
		if err := conn.WriteJSON(authChallenge); err != nil {
			t.Logf("Failed to write challenge: %v", err)
			return
		}

		// Read auth response
		var authResponse map[string]string
		if err := conn.ReadJSON(&authResponse); err != nil {
			t.Logf("Failed to read auth response: %v", err)
			return
		}

		// Verify signature
		pubKeyBytes, _ := base64.StdEncoding.DecodeString(authResponse["device_public_key"])
		signatureBytes, _ := base64.StdEncoding.DecodeString(authResponse["signature"])

		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubKeyBytes)
		pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

		sigR := new(big.Int).SetBytes(signatureBytes[0:32])
		sigS := new(big.Int).SetBytes(signatureBytes[32:64])

		hash := sha256.Sum256(challenge)
		if !ecdsa.Verify(pubKey, hash[:], sigR, sigS) {
			authFailure := map[string]string{"type": "auth_failure", "error": "invalid signature"}
			conn.WriteJSON(authFailure)
			return
		}

		// Send auth success
		authSuccess := map[string]string{"type": "auth_success", "fingerprint": "test"}
		conn.WriteJSON(authSuccess)

		// Keep connection open briefly
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	// Convert http://... to ws://...
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Generate server keypair for envelope crypto
	serverPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create client and connect
	client := NewClient(wsURL, privKey, &serverPrivKey.PublicKey)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if !client.IsConnected() {
		t.Error("Expected client to be connected")
	}

	client.Close()
}

// Test auth failure due to invalid signature
func TestClient_Connect_AuthFailure(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()

		// Send auth challenge
		challenge := make([]byte, 32)
		rand.Read(challenge)
		authChallenge := map[string]string{
			"type":       "auth_challenge",
			"challenge":  base64.StdEncoding.EncodeToString(challenge),
			"expires_at": time.Now().Add(30 * time.Second).Format(time.RFC3339),
		}
		conn.WriteJSON(authChallenge)

		// Read auth response
		var authResponse map[string]string
		conn.ReadJSON(&authResponse)

		// Always reject
		authFailure := map[string]string{"type": "auth_failure", "error": "invalid signature"}
		conn.WriteJSON(authFailure)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Generate server keypair for envelope crypto
	serverPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	client := NewClient(wsURL, privKey, &serverPrivKey.PublicKey)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err == nil {
		t.Fatal("Expected auth failure error")
	}

	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("Expected 'authentication failed' error, got: %v", err)
	}
}

// Test signature format (64 bytes, R||S)
func TestClient_SignatureFormat(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challenge := make([]byte, 32)
	rand.Read(challenge)

	signature, err := crypto.Sign(privKey, challenge)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) != 64 {
		t.Errorf("Expected 64-byte signature, got %d bytes", len(signature))
	}

	// Extract R and S
	r := new(big.Int).SetBytes(signature[0:32])
	s := new(big.Int).SetBytes(signature[32:64])

	// Verify low-S normalization
	curve := privKey.Curve
	halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		t.Error("Signature S component exceeds N/2 (not low-S normalized)")
	}

	// Verify signature is valid
	hash := sha256.Sum256(challenge)
	if !ecdsa.Verify(&privKey.PublicKey, hash[:], r, s) {
		t.Error("Signature verification failed")
	}
}

// Test public key compression format
func TestClient_PublicKeyCompression(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	compressed := crypto.CompressPublicKey(&privKey.PublicKey)

	if len(compressed) != 33 {
		t.Errorf("Expected 33-byte compressed key, got %d bytes", len(compressed))
	}

	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		t.Errorf("Expected prefix 0x02 or 0x03, got 0x%02x", compressed[0])
	}

	// Verify it can be decompressed
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		t.Fatal("Failed to decompress public key")
	}

	if x.Cmp(privKey.PublicKey.X) != 0 || y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Error("Decompressed key doesn't match original")
	}
}

// Test challenge handler callback
func TestClient_ChallengeHandler(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challengeReceived := make(chan Challenge, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()

		// Auth flow
		challenge := make([]byte, 32)
		rand.Read(challenge)
		authChallenge := map[string]string{
			"type":       "auth_challenge",
			"challenge":  base64.StdEncoding.EncodeToString(challenge),
			"expires_at": time.Now().Add(30 * time.Second).Format(time.RFC3339),
		}
		conn.WriteJSON(authChallenge)

		var authResponse map[string]string
		conn.ReadJSON(&authResponse)

		authSuccess := map[string]string{"type": "auth_success", "fingerprint": "test"}
		conn.WriteJSON(authSuccess)

		// Send auth_request challenge
		authRequest := map[string]interface{}{
			"type":         "auth_request",
			"challenge_id": "test-123",
			"challenge":    base64.StdEncoding.EncodeToString([]byte("test-challenge")),
			"expires_at":   time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		}
		conn.WriteJSON(authRequest)

		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Generate server keypair for envelope crypto
	serverPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	client := NewClient(wsURL, privKey, &serverPrivKey.PublicKey)

	client.OnChallenge(func(c Challenge) error {
		challengeReceived <- c
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	select {
	case c := <-challengeReceived:
		if c.Type != "auth_request" {
			t.Errorf("Expected type 'auth_request', got %q", c.Type)
		}
		if c.ChallengeID != "test-123" {
			t.Errorf("Expected challenge_id 'test-123', got %q", c.ChallengeID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Challenge handler not called within timeout")
	}
}

// Test graceful disconnect
func TestClient_Close(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()

		challenge := make([]byte, 32)
		rand.Read(challenge)
		authChallenge := map[string]string{
			"type":       "auth_challenge",
			"challenge":  base64.StdEncoding.EncodeToString(challenge),
			"expires_at": time.Now().Add(30 * time.Second).Format(time.RFC3339),
		}
		conn.WriteJSON(authChallenge)

		var authResponse map[string]string
		conn.ReadJSON(&authResponse)

		authSuccess := map[string]string{"type": "auth_success", "fingerprint": "test"}
		conn.WriteJSON(authSuccess)

		// Wait for close
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Generate server keypair for envelope crypto
	serverPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	client := NewClient(wsURL, privKey, &serverPrivKey.PublicKey)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if !client.IsConnected() {
		t.Error("Expected client to be connected")
	}

	if err := client.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Give messageLoop time to detect closure
	time.Sleep(100 * time.Millisecond)

	if client.IsConnected() {
		t.Error("Expected client to be disconnected after Close()")
	}
}

// Test message loop context cancellation
func TestClient_ContextCancellation(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()

		challenge := make([]byte, 32)
		rand.Read(challenge)
		authChallenge := map[string]string{
			"type":       "auth_challenge",
			"challenge":  base64.StdEncoding.EncodeToString(challenge),
			"expires_at": time.Now().Add(30 * time.Second).Format(time.RFC3339),
		}
		conn.WriteJSON(authChallenge)

		var authResponse map[string]string
		conn.ReadJSON(&authResponse)

		authSuccess := map[string]string{"type": "auth_success", "fingerprint": "test"}
		conn.WriteJSON(authSuccess)

		// Keep connection open
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Generate server keypair for envelope crypto
	serverPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	client := NewClient(wsURL, privKey, &serverPrivKey.PublicKey)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Cancel context
	cancel()
	time.Sleep(200 * time.Millisecond)

	// messageLoop should have exited, connection should close
	client.Close()
}

// Test getStringFromMap helper
func TestGetString(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]interface{}
		key      string
		expected string
	}{
		{
			name:     "key exists with string value",
			m:        map[string]interface{}{"foo": "bar"},
			key:      "foo",
			expected: "bar",
		},
		{
			name:     "key does not exist",
			m:        map[string]interface{}{"foo": "bar"},
			key:      "baz",
			expected: "",
		},
		{
			name:     "key exists with non-string value",
			m:        map[string]interface{}{"foo": 123},
			key:      "foo",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringFromMap(tt.m, tt.key)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// Test authenticate error paths
func TestClient_Authenticate_Errors(t *testing.T) {
	t.Skip("TODO: Rewrite for SIGIL-CONV-V1 envelope protocol")

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("invalid challenge base64", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _ := upgrader.Upgrade(w, r, nil)
			defer conn.Close()

			// Send auth challenge with invalid base64
			authChallenge := map[string]string{
				"type":       "auth_challenge",
				"challenge":  "!!!invalid-base64!!!",
				"expires_at": time.Now().Add(30 * time.Second).Format(time.RFC3339),
			}
			conn.WriteJSON(authChallenge)
		}))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

		// Generate server keypair for envelope crypto
		serverPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		client := NewClient(wsURL, privKey, &serverPrivKey.PublicKey)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := client.Connect(ctx)
		if err == nil || !strings.Contains(err.Error(), "failed to decode challenge") {
			t.Errorf("Expected decode error, got: %v", err)
		}
	})

	t.Run("wrong message type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _ := upgrader.Upgrade(w, r, nil)
			defer conn.Close()

			// Send wrong message type
			wrongMsg := map[string]string{
				"type": "wrong_type",
			}
			conn.WriteJSON(wrongMsg)
		}))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

		// Generate server keypair for envelope crypto
		serverPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		client := NewClient(wsURL, privKey, &serverPrivKey.PublicKey)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := client.Connect(ctx)
		if err == nil || !strings.Contains(err.Error(), "expected auth_challenge") {
			t.Errorf("Expected message type error, got: %v", err)
		}
	})
}
