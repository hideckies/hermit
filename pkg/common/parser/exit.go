package parser

import (
	"github.com/alecthomas/kong"

	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type exitCmd struct{}

func (c *exitCmd) Run(
	realCtx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if err := handler.HandleExit(serverState, clientState); err != nil {
		return err
	}
	return nil
}
