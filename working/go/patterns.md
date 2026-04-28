# Go Patterns — cli-device

Approved Go patterns and code examples used in this codebase.

## Domain-Separated Cryptographic Signatures

**Pattern:** Prepend domain-specific tag to message before signing to prevent cross-protocol replay attacks.

**Implementation:**

```go
// Domain separation tags (NUL-terminated)
var (
	DomainAuth    = []byte("SIGIL-AUTH-V1\x00")
	DomainMPA     = []byte("SIGIL-MPA-V1\x00")
	DomainDecrypt = []byte("SIGIL-DECRYPT-V1\x00")
)

// SignWithDomain creates a domain-separated ECDSA signature
func SignWithDomain(privateKey *ecdsa.PrivateKey, domain []byte, message []byte) ([]byte, error) {
	taggedInput := append(domain, message...)
	return Sign(privateKey, taggedInput)
}
```

**Rationale:**
- Prevents signature from one flow (auth) being replayed in another (MPA)
- Tag includes version suffix for future migration path
- NUL byte (`\x00`) prevents ambiguity in tag parsing

**Reference:** `internal/crypto/ecdsa.go`, `api/domain-separation.md`

---

## Action Context Binding via Canonical JSON Hash

**Pattern:** Bind user-visible action to cryptographic signature via SHA256(canonical_json(action_context)).

**Implementation:**

```go
func ComputeActionContextHash(actionContext interface{}) ([]byte, error) {
	var canonical []byte

	if actionContext == nil {
		// Empty action context = canonical '{}'
		canonical = []byte("{}")
	} else {
		// Marshal to JSON first, then canonicalize via RFC 8785 (JCS)
		jsonBytes, err := json.Marshal(actionContext)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal action_context: %w", err)
		}
		canonical, err = jcs.Transform(jsonBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to canonicalize action_context: %w", err)
		}
	}

	hash := sha256.Sum256(canonical)
	return hash[:], nil
}
```

**Rationale:**
- Prevents server from swapping action after user approves (e.g., "view dashboard" → "delete all data")
- RFC 8785 canonical JSON ensures deterministic hash across implementations
- Empty action_context (`{}`) has fixed hash: `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`

**Reference:** `internal/crypto/ecdsa.go`, `api/domain-separation.md`, RFC 8785

---

## Test Vector-Based Cryptographic Testing

**Pattern:** Validate cryptographic implementations against canonical test vectors to ensure cross-implementation compatibility.

**Implementation:**

```go
func TestAuthV1DomainSeparation(t *testing.T) {
	data, err := os.ReadFile("testdata/domain-separation/auth-v1.json")
	if err != nil {
		t.Fatalf("Failed to read auth-v1.json: %v", err)
	}

	var vectors struct {
		Vectors []struct {
			Name                   string                 `json:"name"`
			PrivateKeyHex          string                 `json:"private_key_hex"`
			ActionContextJSON      map[string]interface{} `json:"action_context_json"`
			ActionContextHashHex   string                 `json:"action_context_hash_hex"`
			ExpectedSignatureHex   string                 `json:"expected_signature_hex"`
			// ... other fields
		} `json:"vectors"`
	}

	json.Unmarshal(data, &vectors)

	for _, tc := range vectors.Vectors {
		t.Run(tc.Name, func(t *testing.T) {
			// Compute action hash
			actionHash, _ := ComputeActionContextHash(tc.ActionContextJSON)
			// Verify hash matches expected
			if hex.EncodeToString(actionHash) != tc.ActionContextHashHex {
				t.Errorf("Action hash mismatch")
			}
			// ... verify signature
		})
	}
}
```

**Rationale:**
- Test vectors are canonical reference for cross-implementation compatibility
- Vendored into `internal/crypto/testdata/` to avoid external dependencies in CI
- Go stdlib uses randomized ECDSA (not RFC 6979), so we verify test vector signatures are valid, but produce our own randomized signatures

**Reference:** `internal/crypto/domain_test.go`, `api/test-vectors/domain-separation/`

---

## Error Wrapping with Context

**Pattern:** Wrap errors with context at each layer using `%w` verb to preserve error chain.

**Implementation:**

```go
actionHash, err := crypto.ComputeActionContextHash(actionCtx)
if err != nil {
	return fmt.Errorf("failed to compute action context hash: %w", err)
}
```

**Rationale:**
- Preserves original error for `errors.Is()` and `errors.As()` checks
- Adds context at each layer without losing information
- Go convention: lowercase first letter, no trailing punctuation

**Reference:** Standard Go error handling, all files in codebase

---

## Table-Driven Tests with Subtests

**Pattern:** Use `t.Run()` with test case tables for comprehensive, organized test coverage.

**Implementation:**

```go
func TestDomainSeparation(t *testing.T) {
	for _, tc := range vectors.Vectors {
		t.Run(tc.Name, func(t *testing.T) {
			// Test case logic here
		})
	}
}
```

**Rationale:**
- Each test case runs independently (can be run in isolation with `-run`)
- Clear test organization and output
- Easy to add new test cases

**Reference:** All `*_test.go` files in codebase

---

## Byte Slice Pre-Allocation

**Pattern:** Pre-allocate slices when size is known to avoid repeated allocations.

**Implementation:**

```go
signature := make([]byte, 64)
r.FillBytes(signature[0:32])
s.FillBytes(signature[32:64])
```

**Rationale:**
- Avoids multiple allocations during append operations
- More efficient for fixed-size data structures
- Common in crypto code where sizes are known (P-256 signatures are always 64 bytes)

**Reference:** `internal/crypto/ecdsa.go` (Sign function)

---

## Defer for Resource Cleanup

**Pattern:** Use `defer` immediately after acquiring a resource to ensure cleanup.

**Implementation:**

```go
resp, err := http.Post(respondURL, "application/json", bytes.NewReader(reqJSON))
if err != nil {
	return fmt.Errorf("failed to POST response: %w", err)
}
defer resp.Body.Close()
```

**Rationale:**
- Ensures resource cleanup even if function returns early
- Places cleanup code visually close to acquisition
- Go convention for idiomatic cleanup

**Reference:** `cmd/sigil-device/cmd_respond.go`, `cmd/sigil-device/cmd_pair.go`
