package parser

import (
	"github.com/alecthomas/kong"

	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type versionCmd struct{}

func (c *versionCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	handler.HandleVersion(serverState, clientState)
	return nil
}
