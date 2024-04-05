package parser

import (
	"github.com/alecthomas/kong"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type payloadGenCmd struct{}

func (c *payloadGenCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandlePayloadGen(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type payloadCmd struct {
	Gen payloadGenCmd `cmd:"" help:"Generate a payload."`
}
