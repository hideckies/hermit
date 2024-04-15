package crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
)

// Generate key/IV and Base64 encode.
func generateRandomKeyAndIV(keyLen int, ivLen int) (key []byte, key64 string, iv []byte, iv64 string, err error) {
	key = make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, "", nil, "", err
	}
	key64 = base64.StdEncoding.EncodeToString(key)

	iv = make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, "", nil, "", err
	}
	iv64 = base64.StdEncoding.EncodeToString(iv)

	return key, key64, iv, iv64, nil
}

// Decode Base64 key/IV to bytes
func decodeKeyAndIV(key64 string, iv64 string) (key []byte, iv []byte, err error) {
	key, err = base64.StdEncoding.DecodeString(key64)
	if err != nil {
		return nil, nil, err
	}

	iv, err = base64.StdEncoding.DecodeString(iv64)
	if err != nil {
		return nil, nil, err
	}

	return key, iv, nil
}

// Padding by PKCS#7
func padPKCS7(data []byte, blockSize int) []byte {
	padSize := blockSize - (len(data) % blockSize)
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(data, pad...)
}

// Unpadding by PKCS#7
func unpadPKCS7(data []byte) []byte {
	padSize := int(data[len(data)-1])
	return data[:len(data)-padSize]
}

func XOR(input, key string) (output string) {
	for i := 0; i < len(input); i++ {
		output += string(input[i] ^ key[i%len(key)])
	}
	return output
}
