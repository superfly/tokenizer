package macaroon

import "crypto/sha256"

const Location = "tokenizer"

func KeyFingerprint(key []byte) []byte {
	sum := sha256.Sum256(key)
	return sum[:16]
}
