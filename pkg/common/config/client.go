package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
)

type server struct {
	Host    string   `json:"host"`
	Port    uint16   `json:"port"`
	Domains []string `json:"domains"`
}

type ClientConfig struct {
	Uuid          string `json:"uuid"`
	Operator      string `json:"operator"`
	Server        server `json:"server"`
	CaCertificate string `json:"caCertificate"`
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"privateKey"`
}

func NewClientConfig(
	operatorName string,
	host string,
	port uint16,
	domains []string,
	caCert string,
	cert string,
	privateKey string,
) *ClientConfig {
	uuid := uuid.NewString()
	name := operatorName
	if operatorName == "" {
		name = utils.GenerateRandomRoleName(false, "")
	}

	return &ClientConfig{
		Uuid:          uuid,
		Operator:      name,
		Server:        server{Host: host, Port: port, Domains: domains},
		CaCertificate: caCert,
		Certificate:   cert,
		PrivateKey:    privateKey,
	}
}

func (c *ClientConfig) WriteJson() error {
	configsDir, err := meta.GetConfigsDir(false)
	if err != nil {
		return err
	}

	configPath := fmt.Sprintf("%s/client-config-%s.json", configsDir, c.Operator)

	data, _ := json.MarshalIndent(c, "", " ")
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		return err
	}

	stdout.LogSuccess(fmt.Sprintf("A client config file generated: %s", color.HiGreenString(configPath)))
	stdout.LogSuccess("Transfer this file to the computer where the C2 client runs.")
	return nil
}

func ReadClientConfigJson(configPath string, isClient bool) (*ClientConfig, error) {
	configJson, err := getConfigJson(configPath, CONFIG_TYPE_CLIENT, isClient)
	if err != nil {
		return nil, err
	}
	defer configJson.Close()

	configData, err := io.ReadAll(configJson)
	if err != nil {
		return nil, err
	}

	var clientConfig ClientConfig
	json.Unmarshal(configData, &clientConfig)

	return &clientConfig, nil
}
