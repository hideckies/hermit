package crypt

import "encoding/hex"

// TODO: Implement encryption
func Encrypt(plaintext string) string {
	// Encode to HEX
	ciphertext := hex.EncodeToString([]byte(plaintext))
	return ciphertext
}

// TODO: Implement decryption
func Decrypt(ciphertext string) (string, error) {
	// Decode HEX
	decoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	plaintext := string(decoded)
	return plaintext, nil
}

// TODO: Implement encryption
func EncryptData(plaindata []byte) []byte {
	cipherdata := make([]byte, hex.EncodedLen(len(plaindata)))
	hex.Encode(cipherdata, plaindata)
	return cipherdata
}

// TODO: Implement decryption
func DecryptData(cipherdata []byte) ([]byte, error) {
	plaindata := make([]byte, hex.DecodedLen(len(cipherdata)))
	_, err := hex.Decode(plaindata, cipherdata)
	if err != nil {
		return nil, err
	}
	return plaindata, nil
}
