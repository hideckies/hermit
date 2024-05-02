package handler

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/client/rpc"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/server/loot"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandleAmLootClear(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		res, err := stdin.Confirm("Are you sure you want to delete all task results?")
		if err != nil {
			return err
		}
		if !res {
			return fmt.Errorf("canceled")
		}

		// Delete all task results files
		err = metafs.DeleteAllAgentLoot(serverState.AgentMode.Name, false)
		if err != nil {
			return err
		}

		stdout.LogSuccess("Loot deleted successfully.")
	} else if clientState.Conf != nil {
		_, err := stdin.Confirm("Are you sure you want to delete all loot gained?")
		if err != nil {
			return err
		}

		stdout.LogSuccess("All loot deleted successfully.")
	}

	return nil
}

func HandleAmLootShow(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
	filter string,
) error {
	if serverState.Conf != nil {
		allLoot, err := loot.GetAllLoot(serverState.AgentMode.Name, filter)
		if err != nil {
			return err
		}
		stdout.LogSuccess("\n")
		fmt.Println(allLoot)
	} else if clientState.Conf != nil {
		allLoot, err := rpc.RequestLootGetAll(clientState, filter)
		if err != nil {
			return err
		}
		stdout.LogSuccess("\n")
		fmt.Println(allLoot)
	}

	return nil
}
