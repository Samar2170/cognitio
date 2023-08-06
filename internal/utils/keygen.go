package utils

import "crypto/rand"

func Generate128BitKey() ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	return key, err
}
