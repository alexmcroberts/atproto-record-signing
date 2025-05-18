package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test that all fields are non-empty
	if keyPair.PrivateKey == "" {
		t.Error("PrivateKey is empty")
	}
	if keyPair.PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	if keyPair.DIDKey == "" {
		t.Error("DIDKey is empty")
	}

	// Test JSON marshaling
	keyPairJSON, err := json.Marshal(keyPair)
	if err != nil {
		t.Fatalf("Failed to marshal key pair: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledKeyPair KeyPair
	if err := json.Unmarshal(keyPairJSON, &unmarshaledKeyPair); err != nil {
		t.Fatalf("Failed to unmarshal key pair: %v", err)
	}

	// Verify unmarshaled values match original
	if unmarshaledKeyPair.PrivateKey != keyPair.PrivateKey {
		t.Error("Unmarshaled PrivateKey does not match original")
	}
	if unmarshaledKeyPair.PublicKey != keyPair.PublicKey {
		t.Error("Unmarshaled PublicKey does not match original")
	}
	if unmarshaledKeyPair.DIDKey != keyPair.DIDKey {
		t.Error("Unmarshaled DIDKey does not match original")
	}
}

func TestSaveKeyPair(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create temporary directory for test
	tempDir := t.TempDir()
	keysDir := filepath.Join(tempDir, "keys")

	// Save key pair
	if err := SaveKeyPair(keyPair, keysDir); err != nil {
		t.Fatalf("Failed to save key pair: %v", err)
	}

	// Verify file exists
	keyPairPath := filepath.Join(keysDir, "keypair.json")
	if _, err := os.Stat(keyPairPath); os.IsNotExist(err) {
		t.Fatalf("Key pair file was not created")
	}

	// Read and verify the saved file
	readJSON, err := os.ReadFile(keyPairPath)
	if err != nil {
		t.Fatalf("Failed to read key pair file: %v", err)
	}

	var readKeyPair KeyPair
	if err := json.Unmarshal(readJSON, &readKeyPair); err != nil {
		t.Fatalf("Failed to unmarshal read key pair: %v", err)
	}

	// Verify read values match original
	if readKeyPair.PrivateKey != keyPair.PrivateKey {
		t.Error("Read PrivateKey does not match original")
	}
	if readKeyPair.PublicKey != keyPair.PublicKey {
		t.Error("Read PublicKey does not match original")
	}
	if readKeyPair.DIDKey != keyPair.DIDKey {
		t.Error("Read DIDKey does not match original")
	}
}

func TestLoadAndVerifyKeyPair(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test verification
	if err := LoadAndVerifyKeyPair(keyPair); err != nil {
		t.Fatalf("Failed to verify key pair: %v", err)
	}

	// Test with invalid private key
	invalidKeyPair := *keyPair
	invalidKeyPair.PrivateKey = "invalid"
	if err := LoadAndVerifyKeyPair(&invalidKeyPair); err == nil {
		t.Error("Expected error with invalid private key, got nil")
	}

	// Test with invalid DID key
	invalidKeyPair = *keyPair
	invalidKeyPair.DIDKey = "invalid"
	if err := LoadAndVerifyKeyPair(&invalidKeyPair); err == nil {
		t.Error("Expected error with invalid DID key, got nil")
	}
}
