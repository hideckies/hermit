package parser

import (
	"github.com/alecthomas/kong"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type amLootClearCmd struct{}

func (c *amLootClearCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAmLootClear(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amLootShowCmd struct {
	Filter string `short:"f" help:"Filter by strings."`
}

func (c *amLootShowCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAmLootShow(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amLootCmd struct {
	Clear amLootClearCmd `cmd:"" help:"Remove all loot."`
	Show  amLootShowCmd  `cmd:"" help:"Print loot gained from target computer."`
}
