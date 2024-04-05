package parser

import (
	"github.com/alecthomas/kong"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

type listenerNewCmd struct {
	Url     string   `short:"u" required:"" default:"https://${default_bind_addr}:${default_bind_port}" help:"Specify URL"`
	Domains []string `short:"d" optional:"" name:"domains" default:"${default_domains}" help:"Domains."`
}

func (c *listenerNewCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleListenerNew(c.Url, c.Domains, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type listenerStartCmd struct {
	Id uint `arg:"" required:""`
}

func (c *listenerStartCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleListenerStartById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type listenerStopCmd struct {
	Id uint `arg:"" required:""`
}

func (c *listenerStopCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleListenerStopById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type listenerDeleteCmd struct {
	Id uint `arg:"" required:""`
}

func (c *listenerDeleteCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleListenerDeleteById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type listenerInfoCmd struct {
	Id uint `arg:"" required:""`
}

func (c *listenerInfoCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleListenerInfoById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type listenerListCmd struct{}

func (c *listenerListCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleListenerList(serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type listenerPayloadsCmd struct {
	Id uint `arg:"" required:""`
}

func (c *listenerPayloadsCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	err := handler.HandleListenerPayloadsById(c.Id, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type listenerCmd struct {
	New      listenerNewCmd      `cmd:"" help:"Create and start new listener."`
	Start    listenerStartCmd    `cmd:"" help:"Start listener by ID."`
	Stop     listenerStopCmd     `cmd:"" help:"Stop listener by ID."`
	Delete   listenerDeleteCmd   `cmd:"" help:"Delete listener by ID."`
	Info     listenerInfoCmd     `cmd:"" help:"Print listener info by ID."`
	List     listenerListCmd     `cmd:"" help:"Print all listeners info."`
	Payloads listenerPayloadsCmd `cmd:"" help:"Manage payloads hosted on listener."`
}
