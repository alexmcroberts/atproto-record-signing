# AT Protocol Lexicon Record Signing Example

This package demonstrates how to sign and verify AT Protocol lexicon records using cryptographic signatures, following the [AT Protocol cryptography specifications](https://atproto.com/specs/cryptography).

## Overview

The AT Protocol uses two elliptic curves for cryptographic operations:
- `p256` (NIST P-256, secp256r1, prime256v1) - Used in this example
- `k256` (NIST K-256, secp256k1) - Common in Bitcoin and other cryptocurrencies

This example demonstrates:
1. Generating a P-256 key pair
2. Creating a lexicon record with an embedded signature field
3. Signing the record using SHA-256 and ECDSA
4. Verifying the signature
5. Testing invalid signatures (hardcoded values)

## Project Structure

```
jwks/
├── cmd/
│   ├── keys/           # Key generation utilities
│   │   ├── generate_keys.go
│   │   └── generate_keys_test.go
│   └── verify/         # Signature verification utilities
│       ├── sign_verify.go
│       └── sign_verify_test.go
└── README.md
```

## Usage

### Generating Keys

To generate a new key pair:

```bash
# From the jwks directory
go run ./cmd/keys/generate_keys.go
```

This will:
1. Generate a new P-256 key pair
2. Save the keys to `keys/keypair.json`
3. Print the keys in various formats (Multibase and DID)

### Using the Signature Library

The `sign_verify.go` file provides a library for signing and verifying AT Protocol lexicon records. The `LexiconRecord` struct includes a `Signature` field that is used to store the signature after signing:

```go
type LexiconRecord struct {
    Type      string `json:"$type"`
    Text      string `json:"text"`
    CreatedAt string `json:"createdAt"`
    Author    string `json:"author"`
    Signature string `json:"signature,omitempty"` // Used to store the signature
}
```

Here's how to use it in your code:

```go
import "github.com/yourusername/jwks/cmd/verify"

// Create a record (Signature field will be empty initially)
record := verify.LexiconRecord{
    Type:      "app.bsky.feed.post",
    Text:      "Hello, AT Protocol!",
    CreatedAt: "2023-04-10T12:00:00Z",
    Author:    "did:plc:example123",
}

// Sign the record - this will set the Signature field
err := record.Sign(privateKey)
if err != nil {
    log.Fatal(err)
}
// record.Signature now contains the base64-encoded signature

// Verify the signature using the public key and the stored signature
err = record.VerifySignature(publicKey)
if err != nil {
    log.Fatal(err)
}
```

Important notes about the signature field:
1. The `Signature` field is optional in the JSON representation (`omitempty` tag)
2. When signing a record, the `Signature` field is automatically set with the base64-encoded signature
3. When verifying a record, the `Signature` field must be present and contain a valid signature
4. The verification process:
   - Extracts the signature from the `Signature` field
   - Creates a copy of the record with an empty signature
   - Verifies the signature against this unsigned copy
   - Uses the provided public key to verify the signature

### Running Tests

To run all tests:

```bash
# From the jwks directory
go test ./...
```

To run tests with coverage:

```bash
# From the jwks directory
go test -cover ./...
```

## Implementation Details

- Uses P-256 curve (supported by WebCrypto API and hardware security modules)
- Follows AT Protocol's "low-S" signature requirement
- Uses multibase encoding (base58btc) with multicodec prefixes for key representation
- Implements the standard AT Protocol DID key format
- Stores signatures directly in the lexicon record structure
- Uses base64 encoding for signature storage

## Code Structure

### Key Generation (`cmd/keys/`)
- `KeyPair` struct for storing public/private keys
- Functions for generating and saving key pairs
- Tests for key generation and verification

### Signature Verification (`cmd/verify/`)
- `LexiconRecord` struct with embedded signature field
- Methods for handling signatures:
  - `UnsignedBytes()`: Gets record bytes without signature
  - `Sign()`: Signs the record
  - `VerifySignature()`: Verifies the record's signature
- Comprehensive test suite covering:
  - Valid signature creation and verification
  - Invalid signature handling
  - Error cases (nil keys, unsigned records, etc.)

## References

- Based on [Bluesky's Indigo](https://github.com/bluesky-social/indigo) implementation
- Follows [AT Protocol Cryptography Specification](https://atproto.com/specs/cryptography) 