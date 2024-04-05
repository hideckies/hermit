package parser

import (
	"github.com/alecthomas/kong"

	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type operatorInfoCmd struct {
	Id uint `arg:"" required:""`
}

func (c *operatorInfoCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleOperatorInfoById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type operatorListCmd struct{}

func (c *operatorListCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleOperatorList(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type operatorWhoamiCmd struct{}

func (c *operatorWhoamiCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleOperatorWhoami(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type operatorCmd struct {
	Info   operatorInfoCmd   `cmd:"" help:"Print a operator info with a specific ID"`
	List   operatorListCmd   `cmd:"" help:"List operators."`
	Whoami operatorWhoamiCmd `cmd:"" help:"Print the current operator name."`
}
