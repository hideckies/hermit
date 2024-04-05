package parser

import (
	"github.com/alecthomas/kong"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type amTaskClearCmd struct{}

func (c *amTaskClearCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAmTaskClear(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskListCmd struct{}

func (c *amTaskListCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAmTaskList(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskCmd struct {
	Clear amTaskClearCmd `cmd:"" help:"Clear all tasks set."`
	List  amTaskListCmd  `cmd:"" help:"List all tasks that are waiting for results."`
}
