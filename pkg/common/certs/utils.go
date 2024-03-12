package certs

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	insecureRand "math/rand"
	"strings"

	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/utils"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Get Subject Alternate Names
func GetSANs(host string, domains []string) ([]string, error) {
	var sans []string

	if len(domains) > 0 {
		sans = append(sans, domains...)
	}

	sans = append(sans, meta.GetSpecificHost(host))

	// Remove empty
	var sansNoEmpty []string
	for _, san := range sans {
		if san != "" {
			sansNoEmpty = append(sansNoEmpty, san)
		}
	}

	return sansNoEmpty, nil
}

func getRandomInt(max int) int {
	buf := make([]byte, 4)
	rand.Read(buf)
	i := binary.LittleEndian.Uint32(buf)
	return int(i) % max
}

func getRandomOrganization() []string {
	name := orgNames[insecureRand.Intn(len(orgNames))]
	suffix := orgSuffixes[insecureRand.Intn(len(orgSuffixes))]
	switch insecureRand.Intn(4) {
	case 0:
		return []string{strings.TrimSpace(strings.ToLower(name + " " + suffix))}
	case 1:
		return []string{strings.TrimSpace(strings.ToUpper(name + " " + suffix))}
	case 2:
		return []string{strings.TrimSpace(cases.Title(language.Und).String(fmt.Sprintf("%s %s", name, suffix)))}

	default:
		return []string{}
	}
}

func getRandomProvince() string {
	keys := make([]string, 0, len(provinces))
	for key := range provinces {
		keys = append(keys, key)
	}
	return keys[insecureRand.Intn(len(keys))]
}

func getRandomLocality(province string) string {
	locales := provinces[province]
	keys := make([]string, 0, len(locales))
	for k := range locales {
		keys = append(keys, k)
	}
	return keys[insecureRand.Intn(len(keys))]
}

func getRandomStreetAddress(province string, locality string) string {
	addresses := provinces[province][locality]
	return addresses[insecureRand.Intn(len(addresses))]
}

func getRandomPostalCode() []string {
	switch insecureRand.Intn(1) {
	case 0:
		return []string{fmt.Sprintf("%d", insecureRand.Intn(8000)+1000)}
	default:
		return []string{}
	}
}

func getRandomSubject(commonName string) *pkix.Name {
	province := getRandomProvince()
	locale := getRandomLocality(province)
	street := getRandomStreetAddress(province, locale)

	return &pkix.Name{
		Organization:  getRandomOrganization(),
		Country:       []string{"US"},
		Province:      []string{province},
		Locality:      []string{locale},
		StreetAddress: []string{street},
		PostalCode:    getRandomPostalCode(),
		CommonName:    commonName,
	}
}

func getRandomRSAKeySize() int {
	rsaKeySize := []int{2048, 4096}
	return rsaKeySize[utils.GenerateRandomInt(0, len(rsaKeySize)-1)]
}

func getPublicKey(privateKey interface{}) interface{} {
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func getPEMBlockForKey(privateKey interface{}) (*pem.Block, error) {
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		data, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: data}, nil
	case *rsa.PrivateKey:
		data := x509.MarshalPKCS1PrivateKey(key)
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: data}, nil
	default:
		return nil, nil
	}
}
