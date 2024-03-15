package config

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdout"
)

const (
	CONFIG_TYPE_SERVER = "server"
	CONFIG_TYPE_CLIENT = "client"
)

func getConfigJson(configPath string, configType string, isClient bool) (*os.File, error) {
	if configPath == "" {
		// Read from the default config path if the 'config' option is not set.
		configsDir, err := metafs.GetConfigsDir(isClient)
		if err != nil {
			return nil, err
		}

		switch configType {
		case CONFIG_TYPE_CLIENT:
			configPath = fmt.Sprintf("%s/client-config.json", configsDir)
		case CONFIG_TYPE_SERVER:
			configPath = "./config.json"
		default:
		}
	}

	stdout.LogInfo(fmt.Sprintf("Loading the configuration from '%s'", color.HiGreenString(configPath)))

	configJson, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	return configJson, nil
}
