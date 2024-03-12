package certs

import (
	"github.com/hideckies/hermit/pkg/common/config"
	"github.com/hideckies/hermit/pkg/common/meta"
)

func RPCGenerateCertificates(conf *config.ServerConfig) error {
	sans, err := GetSANs(conf.Host, conf.Domains)
	if err != nil {
		return err
	}

	caType := CATYPE_RPC
	// Check if the CA certificate eixsts. If does not, generate new certificates for CA, server, client.
	_, _, err = GetCAPEM(caType, "")
	if err != nil {
		caCertPEM, caKeyPEM, err := GenerateECCCertificate(caType, sans, true, false, "")
		if err != nil {
			return err
		}
		err = SaveCertificate(caType, true, false, "", caCertPEM, caKeyPEM)
		if err != nil {
			return err
		}

		// Server certificate
		serverCertPEM, serverKeyPEM, err := GenerateECCCertificate(caType, sans, false, false, "")
		if err != nil {
			return err
		}
		err = SaveCertificate(caType, false, false, "", serverCertPEM, serverKeyPEM)
		if err != nil {
			return err
		}

		// Client certificate
		clientCertPEM, clientKeyPEM, err := GenerateECCCertificate(caType, sans, false, true, "")
		if err != nil {
			return err
		}
		err = SaveCertificate(caType, false, true, "", clientCertPEM, clientKeyPEM)
		if err != nil {
			return err
		}

		// Save the config json used for the C2 client
		clientConfig := config.NewClientConfig(
			"",
			meta.GetSpecificHost(conf.Host),
			conf.Port,
			conf.Domains,
			string(caCertPEM),
			string(clientCertPEM),
			string(clientKeyPEM),
		)
		err = clientConfig.WriteJson()
		if err != nil {
			return err
		}
	}

	return nil
}
