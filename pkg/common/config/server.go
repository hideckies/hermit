package config

import (
	"encoding/json"
	"io"
)

type listener struct {
	FakeRoutes      map[string][]string `json:"fakeRoutes"`
	ResponseHeaders []string            `json:"responseHeaders"`
}

type ServerConfig struct {
	Host     string   `json:"host"`
	Port     uint16   `json:"port"`
	Domains  []string `json:"domains"`
	Listener listener `json:"listeners"`
}

func ReadServerConfigJson(configPath string, isClient bool) (*ServerConfig, error) {
	configJson, err := getConfigJson(configPath, CONFIG_TYPE_SERVER, isClient)
	if err != nil {
		return nil, err
	}
	defer configJson.Close()

	configData, err := io.ReadAll(configJson)
	if err != nil {
		return nil, err
	}

	var serverConfig ServerConfig
	json.Unmarshal(configData, &serverConfig)

	return &serverConfig, nil
}
