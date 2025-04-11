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

## Usage

```bash
go run sign_verify.go
```

The script will:
1. Generate a new key pair
2. Run two test cases:
   - Working Record Test: Creates, signs, and verifies a valid record
   - Broken Record Test: Demonstrates verification failure with a hardcoded signature

## Implementation Details

- Uses P-256 curve (supported by WebCrypto API and hardware security modules)
- Follows AT Protocol's "low-S" signature requirement
- Uses multibase encoding (base58btc) with multicodec prefixes for key representation
- Implements the standard AT Protocol DID key format
- Stores signatures directly in the lexicon record structure
- Uses base64 encoding for signature storage

## Code Structure

The example includes:
- `LexiconRecord` struct with embedded signature field
- Methods for handling signatures:
  - `UnsignedBytes()`: Gets record bytes without signature
  - `Sign()`: Signs the record
  - `VerifySignature()`: Verifies the record's signature
- Test functions demonstrating both valid and invalid signatures

## References

- Based on [Bluesky's Indigo](https://github.com/bluesky-social/indigo) implementation
- Follows [AT Protocol Cryptography Specification](https://atproto.com/specs/cryptography) 