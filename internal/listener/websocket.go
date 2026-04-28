package listener

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sigilauth/cli-device/internal/envelope"
)

type Client struct {
	url              string
	devicePrivKey    *ecdsa.PrivateKey
	serverPubKey     *ecdsa.PublicKey
	conn             *websocket.Conn
	mu               sync.Mutex
	connected        bool
	challengeHandler ChallengeHandler
	nonceStore       map[string]bool
}

func NewClient(url string, devicePrivKey *ecdsa.PrivateKey, serverPubKey *ecdsa.PublicKey) *Client {
	return &Client{
		url:           url,
		devicePrivKey: devicePrivKey,
		serverPubKey:  serverPubKey,
		nonceStore:    make(map[string]bool),
	}
}

func (c *Client) Connect(ctx context.Context) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, c.url, nil)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.connected = true
	c.mu.Unlock()

	// Start message loop (no auth handshake needed — envelopes provide authentication)
	go c.messageLoop(ctx)

	return nil
}

func (c *Client) messageLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read envelope frame
		var envelopeFrame map[string]string
		if err := c.conn.ReadJSON(&envelopeFrame); err != nil {
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			return
		}

		// Extract envelope
		envelopeB64, ok := envelopeFrame["envelope"]
		if !ok {
			continue
		}

		// Decrypt and verify envelope
		payload, err := envelope.VerifyResponse(c.devicePrivKey, c.serverPubKey, envelopeB64, c.nonceStore)
		if err != nil {
			fmt.Printf("Failed to verify envelope: %v\n", err)
			continue
		}

		// Handle different action types based on payload body
		if c.challengeHandler != nil && payload.Body != nil {
			actionType, _ := payload.Body["action"].(string)

			switch actionType {
			case "challenge.notify", "mpa.notify", "decrypt.notify":
				challenge := Challenge{
					Type:        actionType,
					ChallengeID: getStringFromMap(payload.Body, "challenge_id"),
					Challenge:   getStringFromMap(payload.Body, "challenge"),
					ExpiresAt:   getStringFromMap(payload.Body, "expires_at"),
					Metadata:    payload.Body,
				}
				c.challengeHandler(challenge)
			}
		}
	}
}

func (c *Client) OnChallenge(handler ChallengeHandler) {
	c.challengeHandler = handler
}

func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.connected = false
		return c.conn.Close()
	}
	return nil
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
