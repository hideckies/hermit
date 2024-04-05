package handler

import (
	"fmt"

	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/certs"
	"github.com/hideckies/hermit/pkg/common/config"
	"github.com/hideckies/hermit/pkg/common/stdout"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandleClientConfigGen(serverState *servState.ServerState, clientState *cliState.ClientState) error {
	if serverState.Conf == nil {
		return fmt.Errorf("server can only generate client config")
	}

	stdout.LogInfo("Generating the C2 client config file...")
	stdout.LogInfo("Generating a new client certificate...")

	caType := certs.CATYPE_RPC
	sans, err := certs.GetSANs(serverState.Conf.Host, serverState.Conf.Domains)
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
		"", sans[0], serverState.Conf.Port, serverState.Conf.Domains, string(caCertPEM), string(clientCertPEM), string(clientKeyPEM))
	err = clientConfig.WriteJson()
	if err != nil {
		return err
	}

	return nil
}
