package state

import "github.com/hideckies/hermit/pkg/common/config"

type AgentMode struct {
	Uuid string // agent UUID
	Name string // agent name
	CWD  string // current working directory of agent
}

type ClientState struct {
	Conf      *config.ClientConfig
	AgentMode AgentMode
}

func NewClientState(conf *config.ClientConfig) *ClientState {
	return &ClientState{
		Conf:      conf,
		AgentMode: AgentMode{},
	}
}
