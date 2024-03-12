package handler

import (
	"github.com/hideckies/hermit/pkg/common/certs"
	"github.com/hideckies/hermit/pkg/common/config"
	"github.com/hideckies/hermit/pkg/common/stdout"
)

func ConfigGenClient(addr string, port uint16, domains []string) error {
	stdout.LogInfo("Generating the C2 client config file...")
	stdout.LogInfo("Generating a new client certificate...")

	caType := certs.CATYPE_RPC
	sans, err := certs.GetSANs(addr, domains)
	if err != nil {
		return err
	}

	clientCertPEM, clientKeyPEM, err := certs.GenerateECCCertificate(caType, sans, false, true, "")
	if err != nil {
		return err
	}

	err = certs.SaveCertificate(caType, false, true, "", clientCertPEM, clientKeyPEM)
	if err != nil {
		return err
	}

	caCertPEM, _, err := certs.GetCAPEM(caType, "")
	if err != nil {
		return err
	}

	// Save the config json used for the C2 client
	clientConfig := config.NewClientConfig(
		"", sans[0], port, domains, string(caCertPEM), string(clientCertPEM), string(clientKeyPEM))
	err = clientConfig.WriteJson()
	if err != nil {
		return err
	}

	return nil
}
