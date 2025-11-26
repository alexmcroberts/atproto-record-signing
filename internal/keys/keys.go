package keys

// KeyPair represents a public and private key pair
type KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	DIDKey     string `json:"didKey"`
}

