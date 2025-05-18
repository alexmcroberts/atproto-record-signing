package main

import (
	"log"
	"testing"

	"github.com/bluesky-social/indigo/atproto/crypto"
	"github.com/stretchr/testify/assert"
)

func generateKeys() (crypto.PublicKey, *crypto.PrivateKeyP256) {
	// Generate a new private key (or load an existing one)
	// For demonstration, we'll generate a new P-256 key
	privateKey, err := crypto.GeneratePrivateKeyP256()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Get the public key for verification
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}

	return publicKey, privateKey
}

func TestBrokenRecord(t *testing.T) {
	publicKey, _ := generateKeys()

	record := LexiconRecord{
		Type:      "app.bsky.feed.post",
		Text:      "This is a post with a hardcoded signature - DO NOT TRUST THIS!",
		CreatedAt: "2023-04-10T12:00:00Z",
		Author:    "did:plc:example123",
		Signature: "THIS_IS_A_TERRIBLE_IDEA",
	}

	err := record.VerifySignature(publicKey)
	assert.Error(t, err, "verification should fail with invalid signature")
}

func TestLexiconRecordSignAndVerify(t *testing.T) {
	publicKey, privateKey := generateKeys()

	record := LexiconRecord{
		Type:      "app.bsky.feed.post",
		Text:      "Hello, AT Protocol! This is a signed lexicon record.",
		CreatedAt: "2023-04-10T12:00:00Z",
		Author:    "did:plc:example123",
	}

	// Sign the record
	signErr := record.Sign(privateKey)
	assert.NoError(t, signErr, "should sign record without error")

	// Verify the signature
	verifyErr := record.VerifySignature(publicKey)
	assert.NoError(t, verifyErr, "should verify signature without error")
}

// TestUnsignedRecord verifies that attempting to verify an unsigned record returns an error
func TestUnsignedRecord(t *testing.T) {
	publicKey, _ := generateKeys()

	record := LexiconRecord{
		Type:      "app.bsky.feed.post",
		Text:      "This is an unsigned record",
		CreatedAt: "2023-04-10T12:00:00Z",
		Author:    "did:plc:example123",
		// Signature is intentionally omitted
	}

	err := record.VerifySignature(publicKey)
	assert.Error(t, err, "verification should fail for unsigned record")
	assert.Contains(t, err.Error(), "cannot verify unsigned record")
}

// TestInvalidBase64Signature verifies that attempting to verify a record with invalid base64 signature returns an error
func TestInvalidBase64Signature(t *testing.T) {
	publicKey, _ := generateKeys()

	record := LexiconRecord{
		Type:      "app.bsky.feed.post",
		Text:      "This is a record with invalid base64 signature",
		CreatedAt: "2023-04-10T12:00:00Z",
		Author:    "did:plc:example123",
		Signature: "not-valid-base64!@#$%", // Invalid base64 string
	}

	err := record.VerifySignature(publicKey)
	assert.Error(t, err, "verification should fail for invalid base64 signature")
}

// TestSignWithNilPrivateKey verifies that attempting to sign with a nil private key returns an error
func TestSignWithNilPrivateKey(t *testing.T) {
	record := LexiconRecord{
		Type:      "app.bsky.feed.post",
		Text:      "This is a record that should fail to sign",
		CreatedAt: "2023-04-10T12:00:00Z",
		Author:    "did:plc:example123",
	}

	err := record.Sign(nil)
	assert.Error(t, err, "signing should fail with nil private key")
}

// TestVerifyWithNilPublicKey verifies that attempting to verify with a nil public key returns an error
func TestVerifyWithNilPublicKey(t *testing.T) {
	_, privateKey := generateKeys()

	record := LexiconRecord{
		Type:      "app.bsky.feed.post",
		Text:      "This is a record that should fail to verify",
		CreatedAt: "2023-04-10T12:00:00Z",
		Author:    "did:plc:example123",
	}

	// First sign the record
	err := record.Sign(privateKey)
	assert.NoError(t, err, "should sign record without error")

	// Then try to verify with nil public key
	err = record.VerifySignature(nil)
	assert.Error(t, err, "verification should fail with nil public key")
}
