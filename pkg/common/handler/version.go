package handler

import (
	"github.com/hideckies/hermit/pkg/client/rpc"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/stdout"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandleVersion(serverState *servState.ServerState, clientState *cliState.ClientState) error {
	if serverState.Conf != nil {
		stdout.LogSuccess(meta.GetVersion())
	} else if clientState.Conf != nil {
		// Request to RPC
		res, err := rpc.RequestGetVersion(clientState)
		if err != nil {
			return err
		}
		stdout.LogSuccess(res)
	}
	return nil
}
