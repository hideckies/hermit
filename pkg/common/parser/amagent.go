package parser

import (
	"github.com/alecthomas/kong"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type amAgentInfoCmd struct{}

func (c *amAgentInfoCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAmAgentInfo(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amAgentNoteCmd struct{}

func (c *amAgentNoteCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAmAgentNote(serverState, clientState)
	if err != nil {
		return nil
	}
	return nil
}

type amAgentCmd struct {
	Info amAgentInfoCmd `cmd:"" help:"Print agent info by ID."`
	Note amAgentNoteCmd `cmd:"" help:"Take a note for agent."`
}
