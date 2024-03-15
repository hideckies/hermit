package certs

import (
	"fmt"
	"os"

	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
)

func GetCertificatePath(
	caType string,
	isCA bool,
	isClient bool,
	listenerName string,
) (string, string, error) {
	var certPath string
	var keyPath string

	certsDir, err := metafs.GetCertsDir(listenerName)
	if err != nil {
		return "", "", err
	}

	if isCA {
		certPath = fmt.Sprintf("%s/%s-ca-cert.pem", certsDir, caType)
		keyPath = fmt.Sprintf("%s/%s-ca-key.pem", certsDir, caType)
	} else if isClient {
		certPath = fmt.Sprintf("%s/%s-client-cert.pem", certsDir, caType)
		keyPath = fmt.Sprintf("%s/%s-client-key.pem", certsDir, caType)
	} else {
		certPath = fmt.Sprintf("%s/%s-server-cert.pem", certsDir, caType)
		keyPath = fmt.Sprintf("%s/%s-server-key.pem", certsDir, caType)
	}

	return certPath, keyPath, nil
}

func SaveCertificate(caType string, isCA bool, isClient bool, listenerDir string, certPEM []byte, keyPEM []byte) error {
	certPath, keyPath, err := GetCertificatePath(caType, isCA, isClient, listenerDir)
	if err != nil {
		return err
	}

	err = os.WriteFile(certPath, certPEM, 0644)
	if err != nil {
		return err
	}
	err = os.WriteFile(keyPath, keyPEM, 0644)
	if err != nil {
		return err
	}

	return nil
}
