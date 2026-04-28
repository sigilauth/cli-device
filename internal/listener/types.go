package listener

// Challenge represents an incoming challenge from the server
type Challenge struct {
	Type        string                 `json:"type"`
	ChallengeID string                 `json:"challenge_id"`
	Challenge   string                 `json:"challenge"`
	ExpiresAt   string                 `json:"expires_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ChallengeResponse represents the response to a challenge
type ChallengeResponse struct {
	Type            string `json:"type"`
	ChallengeID     string `json:"challenge_id"`
	DevicePublicKey string `json:"device_public_key"`
	Signature       string `json:"signature"`
	Timestamp       string `json:"timestamp"`
}

// ChallengeHandler processes incoming challenges
type ChallengeHandler func(challenge Challenge) error
