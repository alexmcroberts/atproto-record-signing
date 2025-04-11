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

func main() {
	// Generate a new P-256 key pair
	privateKey, err := crypto.GeneratePrivateKeyP256()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Get the public key
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}

	// Create a key pair object
	keyPair := KeyPair{
		PrivateKey: privateKey.Multibase(),
		PublicKey:  publicKey.Multibase(),
		DIDKey:     publicKey.DIDKey(),
	}

	// Print the keys
	fmt.Println("Private Key (Multibase):", keyPair.PrivateKey)
	fmt.Println("Public Key (Multibase):", keyPair.PublicKey)
	fmt.Println("Public Key (DID):", keyPair.DIDKey)

	// Create a directory for the keys if it doesn't exist
	keysDir := "keys"
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		log.Fatalf("Failed to create keys directory: %v", err)
	}

	// Save the key pair to a file
	keyPairJSON, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal key pair: %v", err)
	}

	keyPairPath := filepath.Join(keysDir, "keypair.json")
	if err := os.WriteFile(keyPairPath, keyPairJSON, 0644); err != nil {
		log.Fatalf("Failed to write key pair: %v", err)
	}

	fmt.Printf("Key pair saved to %s\n", keyPairPath)

	// Demonstrate loading a private key from a multibase string
	loadedPrivateKey, err := crypto.ParsePrivateMultibase(keyPair.PrivateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// Get the public key from the loaded private key
	loadedPublicKey, err := loadedPrivateKey.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get public key from loaded private key: %v", err)
	}

	// Verify that the loaded public key matches the original
	if loadedPublicKey.Multibase() != keyPair.PublicKey {
		log.Fatalf("Loaded public key does not match original")
	}

	fmt.Println("Successfully loaded private key and verified public key")

	// Demonstrate loading a public key from a DID key string
	loadedPublicKeyFromDID, err := crypto.ParsePublicDIDKey(keyPair.DIDKey)
	if err != nil {
		log.Fatalf("Failed to parse public key from DID: %v", err)
	}

	// Verify that the loaded public key matches the original
	if loadedPublicKeyFromDID.Multibase() != keyPair.PublicKey {
		log.Fatalf("Loaded public key from DID does not match original")
	}

	fmt.Println("Successfully loaded public key from DID")
}
