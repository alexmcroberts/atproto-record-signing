package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/bluesky-social/indigo/atproto/crypto"
)

// LexiconRecord represents a simple lexicon record that we want to sign
type LexiconRecord struct {
	Type      string `json:"$type"`
	Text      string `json:"text"`
	CreatedAt string `json:"createdAt"`
	Author    string `json:"author"`
	Signature string `json:"signature,omitempty"`
}

// UnsignedBytes returns the bytes of the record without the signature field
func (r *LexiconRecord) UnsignedBytes() ([]byte, error) {
	// Store the signature temporarily
	sig := r.Signature
	// Clear the signature
	r.Signature = ""
	// Marshal the record
	bytes, err := json.Marshal(r)
	// Restore the signature
	r.Signature = sig
	return bytes, err
}

// Sign signs the record using the provided private key
func (r *LexiconRecord) Sign(privateKey crypto.PrivateKey) error {
	bytes, err := r.UnsignedBytes()
	if err != nil {
		return err
	}
	signature, err := privateKey.HashAndSign(bytes)
	if err != nil {
		return err
	}
	r.Signature = base64.RawStdEncoding.EncodeToString(signature)
	return nil
}

// VerifySignature verifies the record's signature using the provided public key
func (r *LexiconRecord) VerifySignature(publicKey crypto.PublicKey) error {
	if r.Signature == "" {
		return fmt.Errorf("cannot verify unsigned record")
	}
	bytes, err := r.UnsignedBytes()
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(r.Signature)
	if err != nil {
		return err
	}
	return publicKey.HashAndVerify(bytes, signature)
}

func testWorkingRecord(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {
	fmt.Println("\n=== Testing Working Record ===")

	// Create a lexicon record
	record := LexiconRecord{
		Type:      "app.bsky.feed.post",
		Text:      "Hello, AT Protocol! This is a signed lexicon record.",
		CreatedAt: "2023-04-10T12:00:00Z",
		Author:    "did:plc:example123",
	}

	// Sign the record
	if err := record.Sign(privateKey); err != nil {
		log.Fatalf("Failed to sign record: %v", err)
	}

	// Verify the signature
	if err := record.VerifySignature(publicKey); err != nil {
		log.Fatalf("Signature verification failed: %v", err)
	}

	fmt.Println("Successfully verified signature!")
}

func testBrokenRecord(publicKey crypto.PublicKey) {
	fmt.Println("\n=== Testing Broken Record ===")

	// Create a record with a hardcoded signature
	record := LexiconRecord{
		Type:      "app.bsky.feed.post",
		Text:      "This is a post with a hardcoded signature - DO NOT TRUST THIS!",
		Signature: "THIS_IS_A_TERRIBLE_IDEA",
	}

	// Try to verify the record with the hardcoded signature
	if err := record.VerifySignature(publicKey); err != nil {
		fmt.Printf("Expected verification failure: %v\n", err)
	} else {
		fmt.Println("WARNING: Hardcoded signature was verified!")
	}
}

func main() {
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

	// Print the public key in DID format for reference
	fmt.Printf("Public Key (DID): %s\n", publicKey.DIDKey())
	fmt.Printf("Public Key (Multibase): %s\n", publicKey.Multibase())

	// Run the tests
	testWorkingRecord(privateKey, publicKey)
	testBrokenRecord(publicKey)
}
