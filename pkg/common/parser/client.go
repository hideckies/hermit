package parser

import (
	"fmt"

	"github.com/alecthomas/kong"

	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type clientConfigGenCmd struct{}

type clientConfigCmd struct {
	Gen clientConfigGenCmd `cmd:"" help:"Generate a config file for the C2 client."`
}

func (c *clientConfigGenCmd) Run(
	realCtx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState != nil {
		if err := handler.HandleClientConfigGen(serverState, nil); err != nil {
			return err
		}
	} else if clientState != nil {
		return fmt.Errorf("client cannot generate config")
	}

	return nil
}
