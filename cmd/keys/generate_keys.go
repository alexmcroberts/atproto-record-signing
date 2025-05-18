package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/bluesky-social/indigo/atproto/crypto"
)

// KeyPair represents a public and private key pair
type KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	DIDKey     string `json:"didKey"`
}

// GenerateKeyPair creates a new P-256 key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := crypto.GeneratePrivateKeyP256()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	return &KeyPair{
		PrivateKey: privateKey.Multibase(),
		PublicKey:  publicKey.Multibase(),
		DIDKey:     publicKey.DIDKey(),
	}, nil
}

// SaveKeyPair saves a key pair to a file
func SaveKeyPair(keyPair *KeyPair, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	keyPairJSON, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key pair: %v", err)
	}

	keyPairPath := filepath.Join(dir, "keypair.json")
	if err := os.WriteFile(keyPairPath, keyPairJSON, 0644); err != nil {
		return fmt.Errorf("failed to write key pair: %v", err)
	}

	return nil
}

// LoadAndVerifyKeyPair loads a key pair from a file and verifies it
func LoadAndVerifyKeyPair(keyPair *KeyPair) error {
	// Demonstrate loading a private key from a multibase string
	loadedPrivateKey, err := crypto.ParsePrivateMultibase(keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Get the public key from the loaded private key
	loadedPublicKey, err := loadedPrivateKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key from loaded private key: %v", err)
	}

	// Verify that the loaded public key matches the original
	if loadedPublicKey.Multibase() != keyPair.PublicKey {
		return fmt.Errorf("loaded public key does not match original")
	}

	// Demonstrate loading a public key from a DID key string
	loadedPublicKeyFromDID, err := crypto.ParsePublicDIDKey(keyPair.DIDKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key from DID: %v", err)
	}

	// Verify that the loaded public key matches the original
	if loadedPublicKeyFromDID.Multibase() != keyPair.PublicKey {
		return fmt.Errorf("loaded public key from DID does not match original")
	}

	return nil
}

func main() {
	// Generate a new key pair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Print the keys
	fmt.Println("Private Key (Multibase):", keyPair.PrivateKey)
	fmt.Println("Public Key (Multibase):", keyPair.PublicKey)
	fmt.Println("Public Key (DID):", keyPair.DIDKey)

	// Save the key pair to a file
	if err := SaveKeyPair(keyPair, "keys"); err != nil {
		log.Fatalf("Failed to save key pair: %v", err)
	}

	fmt.Printf("Key pair saved to keys/keypair.json\n")

	// Verify the key pair
	if err := LoadAndVerifyKeyPair(keyPair); err != nil {
		log.Fatalf("Failed to verify key pair: %v", err)
	}

	fmt.Println("Successfully verified key pair")
}
