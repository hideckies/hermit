package crypt

import "encoding/hex"

func Encrypt(plaintext string) string {
	// TODO: Implement encryption
	// ...

	ciphertext := hex.EncodeToString([]byte(plaintext))
	return ciphertext
}

func Decrypt(ciphertext string) (string, error) {
	decoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	plaintext := string(decoded)

	// TODO: Implement decryption
	// ...

	return plaintext, nil
}

func EncryptData(plaindata []byte) []byte {
	// TODO: Implement encryption
	// ...

	cipherdata := make([]byte, hex.EncodedLen(len(plaindata)))
	hex.Encode(cipherdata, plaindata)

	return cipherdata
}

func DecryptData(cipherdata []byte) ([]byte, error) {
	plaindata := make([]byte, hex.DecodedLen(len(cipherdata)))
	_, err := hex.Decode(plaindata, cipherdata)
	if err != nil {
		return nil, err
	}

	// TODO: Implement decryption
	// ...

	return plaindata, nil
}
