package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

type Pair struct {
	Bytes  []byte
	Base64 string
}

type AES struct {
	Key Pair
	IV  Pair
}

func NewAES() (*AES, error) {
	key, key64, iv, iv64, err := generateRandomKeyAndIV(32, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return &AES{
		Key: Pair{Bytes: key, Base64: key64},
		IV:  Pair{Bytes: iv, Base64: iv64},
	}, nil
}

func NewAESFromBase64Pairs(key64 string, iv64 string) (*AES, error) {
	key, iv, err := decodeKeyAndIV(key64, iv64)
	if err != nil {
		return nil, err
	}

	return &AES{
		Key: Pair{
			Bytes:  key,
			Base64: key64,
		},
		IV: Pair{
			Bytes:  iv,
			Base64: iv64,
		},
	}, nil
}

func (a *AES) Encrypt(plaindata []byte) ([]byte, error) {
	plaindata = padPKCS7(plaindata, aes.BlockSize)

	if len(a.IV.Bytes) != aes.BlockSize {
		return nil, fmt.Errorf("iv length must be same as the block size")
	}

	block, err := aes.NewCipher(a.Key.Bytes)
	if err != nil {
		return nil, err
	}

	cipherdata := make([]byte, aes.BlockSize+len(plaindata))
	copy(cipherdata[:aes.BlockSize], a.IV.Bytes)

	mode := cipher.NewCBCEncrypter(block, a.IV.Bytes)
	mode.CryptBlocks(cipherdata[aes.BlockSize:], plaindata)

	// Base64 encode
	cipherdata64 := make([]byte, base64.StdEncoding.EncodedLen(len(cipherdata)))
	base64.StdEncoding.Encode(cipherdata64, cipherdata)

	return cipherdata64, nil
}

func (a *AES) Decrypt(cipherdata []byte) ([]byte, error) {
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

	if len(a.IV.Bytes) != aes.BlockSize {
		return nil, fmt.Errorf("iv length must be equal to block size")
	}

	if len(cipherDec) < aes.BlockSize {
		return nil, fmt.Errorf("cipherdata too short")
	}

	block, err := aes.NewCipher(a.Key.Bytes)
	if err != nil {
		return nil, err
	}

	// If the cipherDec is not multiple of the block size, cut off the trailing elements to fit block size.
	if len(cipherDec)%aes.BlockSize != 0 {
		newLen := len(cipherDec) - (len(cipherDec) % aes.BlockSize)
		cipherDec = cipherDec[:newLen]
	}

	mode := cipher.NewCBCDecrypter(block, a.IV.Bytes)
	plaindata := make([]byte, len(cipherDec))
	mode.CryptBlocks(plaindata, cipherDec)

	// Unpad
	plaindataUnpad := unpadPKCS7(plaindata)

	return plaindataUnpad, nil
}
