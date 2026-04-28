# sigil-device

CLI tool for Sigil Auth device operations — initialization, pairing, push notification handling, and cryptographic response signing.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install sigilauth/tap/sigil-device
```

### Linux Packages

Download `.deb` or `.rpm` from [Releases](https://github.com/sigilauth/cli-device/releases):

```bash
# Debian/Ubuntu
sudo dpkg -i sigil-device_*.deb

# RHEL/Fedora/CentOS
sudo rpm -i sigil-device_*.rpm
```

### Manual Download

Download binaries from [Releases](https://github.com/sigilauth/cli-device/releases) for:
- macOS (amd64/arm64)
- Linux (amd64/arm64)
- Windows (amd64)

## Quick Start

```bash
# Initialize device identity
sigil-device init

# Display device identity
sigil-device whoami

# Pair with Sigil server
sigil-device pair --server https://sigil.example.com

# Register with push relay
sigil-device register --relay wss://relay.sigilauth.com

# Listen for push notifications
sigil-device listen --relay wss://relay.sigilauth.com
```

## Commands

### init

Initialize device identity by generating ECDSA P-256 keypair and BIP-39 mnemonic.

```bash
sigil-device init
```

**Output:**
- Device public key (compressed, base64)
- Fingerprint (SHA256 of public key)
- Pictogram (5 emojis for visual verification)
- BIP-39 mnemonic (24 words for backup)

**State:**
- Saves to `~/.sigil-device/state.json`
- Saves mnemonic to `~/.sigil-device/mnemonic.txt` (encrypted)

**Exit codes:**
- 0: Success
- 1: Device already initialized

### pair

Pair device with Sigil Auth server.

```bash
sigil-device pair --server https://sigil.example.com
```

**Flags:**
- `--server`, `-s`: Server URL (required)

**Operation:**
1. Loads device identity from state
2. POSTs device public key to `/v1/device/pair`
3. Receives server public key
4. Saves server URL + public key to state

**Exit codes:**
- 0: Success
- 1: Device not initialized or pairing failed

### register

Register device with push relay.

```bash
sigil-device register --relay wss://relay.sigilauth.com
```

**Flags:**
- `--relay`, `-r`: Relay WebSocket URL (required)

**Operation:**
1. Generates mock APNs push token (production apps use real token)
2. POSTs `{fingerprint, push_token, platform}` to relay
3. Relay stores mapping for push delivery

**Exit codes:**
- 0: Success
- 1: Registration failed

### listen

Listen for push notifications via WebSocket.

```bash
sigil-device listen --relay wss://relay.sigilauth.com
```

**Flags:**
- `--relay`, `-r`: Relay WebSocket URL (required)

**Operation:**
1. Connects to relay WebSocket
2. Authenticates via challenge/response:
   - Receives server challenge
   - Signs challenge with device private key
   - Sends `{device_public_key, signature}` (both base64)
3. Listens for push messages:
   - `auth_challenge`: Authentication request
   - `mpa_request`: Multi-party authorization
   - `decrypt_request`: Secure decryption
4. Saves messages to `/tmp/sigil-*.json`

**Exit codes:**
- 0: Success (disconnected cleanly)
- 1: Connection/auth failed

### respond

Respond to authentication challenge.

```bash
# From file
sigil-device respond --challenge-file /tmp/sigil-auth-*.json

# From stdin
cat challenge.json | sigil-device respond
```

**Flags:**
- `--challenge-file`, `-f`: Path to challenge JSON
- `--server`, `-s`: Server URL (optional, defaults to paired server)

**Input format:**
```json
{
  "challenge_id": "uuid",
  "challenge": "base64-encoded-random-bytes",
  "server_signature": "base64-ecdsa-signature",
  "expires_at": "ISO8601-timestamp"
}
```

**Operation:**
1. Verifies server signature on `challenge_id + challenge`
2. Signs challenge with device private key
3. POSTs `{challenge_id, signature}` to `/v1/auth/respond`

**Exit codes:**
- 0: Success
- 1: Verification failed or server rejected

### mpa-respond

Respond to multi-party authorization request.

```bash
# Interactive approval
sigil-device mpa-respond --mpa-file /tmp/sigil-mpa-*.json

# Auto-approve
sigil-device mpa-respond --mpa-file /tmp/sigil-mpa-*.json --auto-approve
```

**Flags:**
- `--mpa-file`, `-f`: Path to MPA request JSON
- `--server`, `-s`: Server URL (optional)
- `--auto-approve`, `-a`: Skip interactive approval prompt

**Input format:**
```json
{
  "request_id": "uuid",
  "action_context": "base64-ecies-encrypted-json",
  "server_signature": "base64-ecdsa-signature",
  "expires_at": "ISO8601-timestamp"
}
```

**Operation:**
1. Verifies server signature on `request_id + action_context`
2. ECIES-decrypts action context (salt = request_id)
3. Displays action type, description, parameters
4. Prompts for approval (unless `--auto-approve`)
5. Signs decrypted action context
6. POSTs `{request_id, fingerprint, signature}` to `/mpa/respond`

**Exit codes:**
- 0: Success
- 1: Verification failed, user rejected, or server error

### decrypt

Decrypt ECIES-encrypted payload and submit plaintext.

```bash
sigil-device decrypt --decrypt-file /tmp/sigil-decrypt-*.json
```

**Flags:**
- `--decrypt-file`, `-f`: Path to decrypt request JSON
- `--server`, `-s`: Server URL (optional)

**Input format:**
```json
{
  "decrypt_id": "uuid",
  "ciphertext": "base64-ecies-ciphertext",
  "server_signature": "base64-ecdsa-signature",
  "expires_at": "ISO8601-timestamp"
}
```

**Operation:**
1. Verifies server signature on `decrypt_id + ciphertext`
2. ECIES-decrypts ciphertext (salt = decrypt_id)
3. POSTs `{decrypt_id, plaintext}` to `/v1/secure/decrypt/respond`

**Exit codes:**
- 0: Success
- 1: Verification failed or decryption error

### whoami

Display device identity.

```bash
sigil-device whoami
```

**Output:**
- Device public key
- Fingerprint
- Pictogram
- Paired server URL (if paired)
- Server public key (if paired)
- Creation timestamp

**Exit codes:**
- 0: Success
- 1: Device not initialized

### unpair

Remove device identity (factory reset).

```bash
sigil-device unpair
```

**Operation:**
- Deletes `~/.sigil-device/state.json`
- Deletes `~/.sigil-device/mnemonic.txt`

**Exit codes:**
- 0: Success
- 1: Device not initialized

## Configuration

### State File

Location: `~/.sigil-device/state.json`

Contains:
- Device public key
- Fingerprint
- Pictogram
- Server URL (after pairing)
- Server public key (after pairing)
- Creation timestamp

### Mnemonic Backup

Location: `~/.sigil-device/mnemonic.txt`

**CRITICAL:** Back up this file securely. It allows device identity recovery.

## Security

- **Private key:** Stored in `~/.sigil-device/key.pem` (PEM-encoded ECDSA P-256)
- **Mnemonic:** Encrypted at rest in `~/.sigil-device/mnemonic.txt`
- **Permissions:** State directory is `0700`, files are `0600`
- **Signature verification:** All server messages verified before processing
- **ECIES encryption:** AES-256-GCM with ECDH key agreement (HKDF-SHA256)

## Development

```bash
# Run tests
go test ./...

# Run tests with race detector
go test -race ./...

# Check coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Build
go build -o sigil-device ./cmd/sigil-device

# Lint
golangci-lint run
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

AGPL-3.0 — see [LICENSE](LICENSE) for details.
