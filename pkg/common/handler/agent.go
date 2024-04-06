package handler

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/hideckies/hermit/pkg/client/rpc"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/server/agent"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func HandleAgentDeleteById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		// Check if the agent exists
		ag, err := serverState.DB.AgentGetById(id)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}

		res, err := stdin.Confirm("Are you sure you want to delete the agent?")
		if err != nil {
			return err
		}
		if !res {
			return fmt.Errorf("canceled")
		}

		// Delete the agent from database
		err = serverState.DB.AgentDeleteById(id)
		if err != nil {
			return err
		}

		// Delete the related folder
		agentDir, err := metafs.GetAgentDir(ag.Name, false)
		if err != nil {
			return err
		}
		err = os.RemoveAll(agentDir)
		if err != nil {
			return err
		}

		stdout.LogSuccess("Agent deleted.")
	} else if clientState.Conf != nil {
		res, err := stdin.Confirm("Are you sure you want to delete the agent?")
		if err != nil {
			return err
		}
		if !res {
			return fmt.Errorf("canceled")
		}

		err = rpc.RequestAgentDeleteById(clientState, id)
		if err != nil {
			return err
		}

		stdout.LogSuccess("Agent deleted.")
	}

	return nil
}

func HandleAgentInfoById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		ag, err := serverState.DB.AgentGetById(id)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}

		agent.PrintAgentDetails(ag)
	} else if clientState.Conf != nil {
		ag, err := rpc.RequestAgentGetById(clientState, id)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}

		agent.PrintAgentDetails(ag)
	}

	return nil
}

func HandleAgentList(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		ags, err := serverState.DB.AgentGetAll()
		if err != nil {
			return err
		}
		agent.PrintAgents(ags)
	} else if clientState.Conf != nil {
		ags, err := rpc.RequestAgentGetAll(clientState)
		if err != nil {
			return err
		}
		agent.PrintAgents(ags)
	}

	return nil
}

func HandleAgentNoteById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		ag, err := serverState.DB.AgentGetById(id)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}

		agNoteFile, err := metafs.GetAgentNoteFile(ag.Name, false)
		if err != nil {
			return err
		}

		cmd := exec.Command("nano", agNoteFile)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		err = cmd.Run()
		if err != nil {
			// If error occured, try 'vim'.
			cmd := exec.Command("vim", agNoteFile)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			return err
		}
	} else if clientState.Conf != nil {
		ag, err := rpc.RequestAgentGetById(clientState, id)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}

		agMemoFile, err := metafs.GetAgentNoteFile(ag.Name, true)
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

func HandleAgentUseById(
	id uint,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		ag, err := serverState.DB.AgentGetById(id)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}

		// Set agent status
		serverState.AgentMode.UUID = ag.Uuid
		serverState.AgentMode.Name = ag.Name

		stdout.LogSuccess("Switched to agent mode.")
	} else if clientState.Conf != nil {
		ag, err := rpc.RequestAgentGetById(clientState, id)
		if err != nil {
			return fmt.Errorf("agent not found: %v", err)
		}

		clientState.AgentMode.UUID = ag.Uuid
		clientState.AgentMode.Name = ag.Name
		clientState.AgentMode.CWD = ""
	}

	return nil
}
