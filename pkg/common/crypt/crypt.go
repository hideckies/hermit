package crypt

import (
	"encoding/base64"
)

func Encrypt(plaindata []byte) ([]byte, error) {
	// TODO: Implement encryption
	// ...

	// Base64 encode
	plain64 := make([]byte, base64.RawStdEncoding.EncodedLen(len(plaindata)))
	base64.RawStdEncoding.Encode(plain64, plaindata)

	// // XOR
	// xored := XOR(string(plain64), "secret")

	// // Base64 encode
	// cipherdata := make([]byte, base64.StdEncoding.EncodedLen(len(xored)))
	// base64.StdEncoding.Encode(cipherdata, []byte(xored))

	return []byte(plain64), nil
}

func Decrypt(cipherdata []byte) ([]byte, error) {
	// Base64 decode
	var cipherDec []byte
	if string(cipherdata)[len(cipherdata)-1] == '=' {
		cipherDec = make([]byte, base64.StdEncoding.DecodedLen(len(cipherdata)))
		_, err := base64.StdEncoding.Decode(cipherDec, cipherdata)
		if err != nil {
			return nil, err
		}
	} else {
		cipherDec = make([]byte, base64.RawStdEncoding.DecodedLen(len(cipherdata)))
		_, err := base64.RawStdEncoding.Decode(cipherDec, cipherdata)
		if err != nil {
			return nil, err
		}
	}

	// XOR
	// xored := XOR(string(cipherDec), "secret")

	// // Base64 decode
	// plaindata := make([]byte, base64.StdEncoding.DecodedLen(len(xored)))
	// _, err = base64.StdEncoding.Decode(plaindata, []byte(xored))
	// if err != nil {
	// 	return nil, err
	// }

	// TODO: Implement decryption
	// ...

	return cipherDec, nil
}
