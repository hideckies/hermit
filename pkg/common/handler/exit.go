package handler

import (
	"fmt"

	cliState "github.com/hideckies/hermit/pkg/client/state"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandleExit(serverState *servState.ServerState, clientState *cliState.ClientState) error {
	if serverState.Conf != nil {
		serverState.Continue = false
	} else if clientState.Conf != nil {
		clientState.Continue = false
	} else {
		return fmt.Errorf("state not set")
	}
	return nil
}
