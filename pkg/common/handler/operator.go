package handler

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/client/rpc"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/server/operator"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandleOperatorInfoById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	var op *operator.Operator
	var err error

	if serverState.Conf != nil {
		op, err = serverState.DB.OperatorGetById(id)
		if err != nil {
			return fmt.Errorf("operator not found: %v", err)
		}
	} else if clientState.Conf != nil {
		// Request to RPC
		op, err = rpc.RequestOperatorGetById(clientState, uint(id))
		if err != nil {
			return fmt.Errorf("operator not found: %v", err)
		}
	}

	operator.PrintOperatorDetails(op)
	return nil
}

func HandleOperatorList(serverState *servState.ServerState, clientState *cliState.ClientState) error {
	if serverState.Conf != nil {
		ops, err := serverState.DB.OperatorGetAll()
		if err != nil {
			return err
		}

		operator.PrintOperators(ops, serverState.Operator.Uuid)
	} else if clientState.Conf != nil {
		// Request to RPC
		ops, err := rpc.RequestOperatorGetAll(clientState)
		if err != nil {
			return err
		}

		operator.PrintOperators(ops, clientState.Conf.Uuid)
	}

	return nil
}

func HandleOperatorWhoami(serverState *servState.ServerState, clientState *cliState.ClientState) error {
	if serverState.Conf != nil {
		stdout.LogSuccess(serverState.Operator.Name)
	} else if clientState.Conf != nil {
		stdout.LogSuccess(clientState.Conf.Operator)
	}

	return nil
}
