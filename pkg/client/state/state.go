package state

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/hideckies/hermit/pkg/common/config"
	"github.com/hideckies/hermit/pkg/protobuf/rpcpb"
)

type AgentMode struct {
	UUID string // agent UUID
	Name string // agent name
	CWD  string // current working directory of agent
}

type ClientState struct {
	Conf      *config.ClientConfig
	RPCClient rpcpb.HermitRPCClient
	Ctx       context.Context
	Parser    *kong.Kong
	AgentMode AgentMode
	Continue  bool // Is console continue or not
}

func NewClientState(conf *config.ClientConfig) *ClientState {
	return &ClientState{
		Conf:      conf,
		AgentMode: AgentMode{},
		Continue:  true,
	}
}
