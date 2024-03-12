package certs

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

const (
	CATYPE_GRPC   = "grpc"
	CATYPE_HTTPS  = "https"
	CATYPE_RPC    = "rpc"
	CATYPE_STAGER = "stage"
)

func GetCAPEM(caType string, listenerName string) ([]byte, []byte, error) {
	caCertPath, caKeyPath, err := GetCertificatePath(caType, true, false, listenerName)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

func GetCA(caType string, listenerName string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, keyPEM, err := GetCAPEM(caType, listenerName)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}
