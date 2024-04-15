package handler

import (
	cliState "github.com/hideckies/hermit/pkg/client/state"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandleAmExit(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Go back to the root console mode
	if serverState.Conf != nil {
		serverState.AgentMode = &servState.AgentMode{}
	} else if clientState.Conf != nil {
		clientState.AgentMode = cliState.AgentMode{}
	}
	return nil
}
