// Certs implement inspired by Sliver (https://github.com/BishopFox/sliver/blob/master/server/certs/certs.go)

package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

const (
	ECCKEY = "ecc"
	RSAKEY = "rsa"
)

var (
	validFor = 3 * (365 * 24 * time.Hour)

	orgNames = []string{
		"",
		"ACME",
		"Partners",
		"Tech",
		"Cloud",
		"Synergy",
		"Test",
		"Debug",
	}

	orgSuffixes = []string{
		"",
		"co",
		"llc",
		"inc",
		"corp",
		"ltd",
	}

	provinces = map[string]map[string][]string{
		"": {
			"": {""},
		},
		"Arizona": {
			"Phoenix":    {""},
			"Mesa":       {""},
			"Scottsdale": {""},
			"Chandler":   {""},
		},
		"California": {
			"San Francisco": {"", "Golden Gate Bridge"},
			"Oakland":       {""},
			"Berkeley":      {""},
			"Palo Alto":     {""},
			"Los Angeles":   {""},
			"San Diego":     {""},
			"San Jose":      {""},
		},
		"Colorado": {
			"Denver":       {""},
			"Boulder":      {""},
			"Aurora":       {""},
			"Fort Collins": {""},
		},
		"Connecticut": {
			"New Haven":  {""},
			"Bridgeport": {""},
			"Stamford":   {""},
			"Norwalk":    {""},
		},
		"Washington": {
			"Seattle": {""},
			"Tacoma":  {""},
			"Olympia": {""},
			"Spokane": {""},
		},
		"Florida": {
			"Miami":        {""},
			"Orlando":      {""},
			"Tampa":        {""},
			"Jacksonville": {""},
		},
		"Illinois": {
			"Chicago":    {""},
			"Aurora":     {""},
			"Naperville": {""},
			"Peoria":     {""},
		},
	}
)

func generateCertificate[K *ecdsa.PrivateKey | *rsa.PrivateKey](
	caType string,
	subject pkix.Name,
	sans []string,
	isCA bool,
	isClient bool,
	listenerName string,
	privateKey K,
) ([]byte, []byte, error) {
	notBefore := time.Now().UTC()
	days := getRandomInt(365) * -1
	notBefore = notBefore.AddDate(0, 0, days)
	notAfter := notBefore.Add(validFor)

	// Serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	var keyUsage x509.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	var extKeyUsage []x509.ExtKeyUsage

	if isCA {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		extKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	} else if isClient {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: isCA,
	}

	if !isClient {
		for _, san := range sans {
			if ip := net.ParseIP(san); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, san)
			}
		}
	}

	var certErr error
	var derBytes []byte
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		derBytes, certErr = x509.CreateCertificate(
			rand.Reader, &template, &template, getPublicKey(privateKey), privateKey)
	} else {
		caCert, caKey, err := GetCA(caType, listenerName)
		if err != nil {
			return []byte{}, []byte{}, err
		}
		derBytes, certErr = x509.CreateCertificate(
			rand.Reader, &template, caCert, getPublicKey(privateKey), caKey)
	}
	if certErr != nil {
		return []byte{}, []byte{}, certErr
	}

	certOut := bytes.NewBuffer([]byte{})
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut := bytes.NewBuffer([]byte{})
	pemBlock, err := getPEMBlockForKey(privateKey)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	pem.Encode(keyOut, pemBlock)

	return certOut.Bytes(), keyOut.Bytes(), nil
}

func GenerateECCCertificate(
	caType string,
	sans []string,
	isCA bool,
	isClient bool,
	listenerName string,
) ([]byte, []byte, error) {
	curves := []elliptic.Curve{elliptic.P521(), elliptic.P384(), elliptic.P256()}
	curve := curves[getRandomInt((len(curves)))]
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	subject := getRandomSubject(sans[0])
	return generateCertificate(caType, *subject, sans, isCA, isClient, listenerName, privateKey)
}

func GenerateRSACertificate(
	caType string,
	sans []string,
	isCA bool,
	isClient bool,
	listenerName string,
) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, getRandomRSAKeySize())
	if err != nil {
		return []byte{}, []byte{}, err
	}
	subject := getRandomSubject(sans[0])
	return generateCertificate(caType, *subject, sans, isCA, isClient, listenerName, privateKey)
}
