package certs

import "github.com/hideckies/hermit/pkg/server/listener"

func HTTPSGenerateCertificates(lis *listener.Listener) error {
	sans, err := GetSANs(lis.Addr, lis.Domains)
	if err != nil {
		return err
	}

	caType := CATYPE_HTTPS
	// Check if the CA certificate eixsts. If does not, generate new certificates for CA, server, client.
	_, _, err = GetCAPEM(caType, lis.Name)
	if err != nil {
		caCertPEM, caKeyPEM, err := GenerateECCCertificate(caType, sans, true, false, lis.Name)
		if err != nil {
			return err
		}
		err = SaveCertificate(caType, true, false, lis.Name, caCertPEM, caKeyPEM)
		if err != nil {
			return err
		}

		// Server certificate
		serverCertPEM, serverKeyPEM, err := GenerateECCCertificate(caType, sans, false, false, lis.Name)
		if err != nil {
			return err
		}
		err = SaveCertificate(caType, false, false, lis.Name, serverCertPEM, serverKeyPEM)
		if err != nil {
			return err
		}

		// Client certificate
		clientCertPEM, clientKeyPEM, err := GenerateECCCertificate(caType, sans, false, true, lis.Name)
		if err != nil {
			return err
		}
		err = SaveCertificate(caType, false, true, lis.Name, clientCertPEM, clientKeyPEM)
		if err != nil {
			return err
		}
	}

	return nil
}
