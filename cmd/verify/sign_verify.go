package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/alex.mcroberts/scratchpad/honk/jwks/internal/keys"
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
	// Create a copy of the record
	recordCopy := *r
	recordCopy.Signature = ""

	return json.Marshal(&recordCopy)
}

// Sign signs the record using the provided private key
func (r *LexiconRecord) Sign(privateKey crypto.PrivateKey) error {
	if privateKey == nil {
		return fmt.Errorf("private key cannot be nil")
	}
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
	if publicKey == nil {
		return fmt.Errorf("public key cannot be nil")
	}
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

func LoadKeyPairFromFile(filename string) (*keys.KeyPair, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var keyPair keys.KeyPair
	if err := json.Unmarshal(data, &keyPair); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return &keyPair, nil
}
