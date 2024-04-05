package handler

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/hideckies/hermit/pkg/client/rpc"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/server/agent"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandleAmAgentInfo(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		ag, err := serverState.DB.AgentGetByUuid(serverState.AgentMode.UUID)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}
		agent.PrintAgentDetails(ag)
	} else if clientState.Conf != nil {
		// Request to RPC
		ags, err := rpc.RequestAgentGetAll(clientState)
		if err != nil {
			return err
		}

		var targetAgent *agent.Agent
		for _, ag := range ags {
			if ag.Uuid == clientState.AgentMode.UUID {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			return fmt.Errorf("agent not found")
		}

		stdout.LogSuccess("")
		agent.PrintAgentDetails(targetAgent)
	}

	return nil
}

func HandleAmAgentNote(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		ag, err := serverState.DB.AgentGetByUuid(serverState.AgentMode.UUID)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}

		agMemoFile, err := metafs.GetAgentNoteFile(ag.Name, false)
		if err != nil {
			return err
		}

		cmd := exec.Command("nano", agMemoFile)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		err = cmd.Run()
		if err != nil {
			return err
		}
	} else if clientState.Conf != nil {
		ags, err := rpc.RequestAgentGetAll(clientState)
		if err != nil {
			return err
		}

		var targetAgent *agent.Agent
		for _, ag := range ags {
			if ag.Uuid == clientState.AgentMode.UUID {
				targetAgent = ag
				break
			}
		}
		if targetAgent == nil {
			return fmt.Errorf("agent not found")
		}

		agMemoFile, err := metafs.GetAgentNoteFile(targetAgent.Name, true)
		if err != nil {
			return err
		}

		cmd := exec.Command("nano", agMemoFile)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		err = cmd.Run()
		if err != nil {
			return err
		}
	}

	return nil
}
