package parser

import (
	"github.com/alecthomas/kong"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type agentDeleteCmd struct {
	Id uint `arg:"" required:""`
}

func (c *agentDeleteCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAgentDeleteById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type agentInfoCmd struct {
	Id uint `arg:"" required:""`
}

func (c *agentInfoCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAgentInfoById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type agentListCmd struct{}

func (c *agentListCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAgentList(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type agentNoteCmd struct {
	Id uint `arg:"" required:""`
}

func (c *agentNoteCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAgentNoteById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type agentUseCmd struct {
	Id uint `arg:"" required:""`
}

func (c *agentUseCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleAgentUseById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type agentCmd struct {
	Delete agentDeleteCmd `cmd:"" help:"Delete an agent by ID."`
	Info   agentInfoCmd   `cmd:"" help:"Print agent info by ID."`
	List   agentListCmd   `cmd:"" help:"Print all agents info."`
	Note   agentNoteCmd   `cmd:"" help:"Take a note for agent by ID."`
	Use    agentUseCmd    `cmd:"" help:"Switch to agent mode."`
}
