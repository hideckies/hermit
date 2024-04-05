package parser

import (
	"github.com/alecthomas/kong"

	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type helpCmd struct {
	Command []string `arg:"" optional:"" help:"Show help on command."`
}

func (c *helpCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleHelp(ctx, c.Command)
	if err != nil {
		return err
	}
	return nil
}
