package console

import (
	"fmt"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/wizard"
	"github.com/hideckies/hermit/pkg/server/agent"
	"github.com/hideckies/hermit/pkg/server/handler"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/loot"
	"github.com/hideckies/hermit/pkg/server/operator"
	"github.com/hideckies/hermit/pkg/server/state"
	"github.com/hideckies/hermit/pkg/server/task"
)

func HandleInvalidCommand(line string) {
	stdout.LogFailed(fmt.Sprintf("Invalid command: `%s`", line))
}

func HandleHelp(ri *readline.Instance, isAgentMode bool) {
	stdin.ConsoleUsage(ri.Stderr(), false, isAgentMode)
}

func HandleVersion() {
	stdout.LogSuccess(meta.GetVersion())
}

func HandleClientConfigGen(serverState *state.ServerState) error {
	err := handler.ConfigGenClient(
		serverState.Conf.Host,
		serverState.Conf.Port,
		serverState.Conf.Domains,
	)
	if err != nil {
		return err
	}
	return nil
}

func HandleOperatorWhoami() {
	stdout.LogSuccess("admin")
}

func HandleOperatorInfoById(line string, argStartIdx int, serverState *state.ServerState, currentUuid string) error {
	operatorId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	op, err := serverState.DB.OperatorGetById(uint(operatorId))
	if err != nil {
		return fmt.Errorf("operator not found: %v", err)
	}

	operator.PrintOperators([]*operator.Operator{op}, currentUuid)
	return nil
}

func HandleOperatorList(serverState *state.ServerState, currentUuid string) error {
	ops, err := serverState.DB.OperatorGetAll()
	if err != nil {
		return err
	}

	operator.PrintOperators(ops, currentUuid)
	return nil
}

func HandleListenerStart(serverState *state.ServerState) error {
	lis, err := wizard.WizardListenerStart(
		meta.GetSpecificHost(serverState.Conf.Host), serverState.Conf.Domains)
	if err != nil {
		return err
	}

	go handler.ListenerStart(lis, serverState)
	err = serverState.Job.WaitListenerStart(serverState.DB, lis)
	if err != nil {
		return err
	}

	stdout.LogSuccess("Listener started.")
	return nil
}

func HandleListenerStartById(line string, argStartIdx int, serverState *state.ServerState) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	lis, err := serverState.DB.ListenerGetById(listenerId)
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}
	if lis.Active {
		return fmt.Errorf("the listener is already running")
	}

	go handler.ListenerStart(lis, serverState)
	err = serverState.Job.WaitListenerStart(serverState.DB, lis)
	if err != nil {
		return err
	}

	stdout.LogSuccess("Listener started.")
	return nil
}

func HandleListenerStopById(line string, argStartIdx int, serverState *state.ServerState) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	lis, err := serverState.DB.ListenerGetById(listenerId)
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}
	if !lis.Active {
		return fmt.Errorf("listener already stopped")
	}

	serverState.Job.ChReqListenerQuit <- lis.Uuid

	err = serverState.Job.WaitListenerStop(serverState.DB, lis)
	if err != nil {
		return err
	}

	stdout.LogSuccess("Listener stopped.")
	return nil
}

func HandleListenerDeleteById(line string, argStartIdx int, serverState *state.ServerState) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}
	lis, err := serverState.DB.ListenerGetById(listenerId)
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}
	if lis.Active {
		return fmt.Errorf("the listener is running. stop it before deleting")
	}

	err = serverState.DB.ListenerDeleteById(listenerId)
	if err != nil {
		return err
	}

	// Delete folder
	listenerDir, err := metafs.GetListenerDir(lis.Name, false)
	if err != nil {
		return err
	}
	err = os.RemoveAll(listenerDir)
	if err != nil {
		return err
	}

	stdout.LogSuccess("The listener deleted.")
	return nil
}

func HandleListenerInfoById(line string, argStartIdx int, serverState *state.ServerState) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	lis, err := serverState.DB.ListenerGetById(listenerId)
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}

	listener.PrintListeners([]*listener.Listener{lis})
	return nil
}

func HandleListenerPayloadsById(line string, argStartIdx int, serverState *state.ServerState) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	lis, err := serverState.DB.ListenerGetById(listenerId)
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}

	// List payloads on the listener
	payloads, err := metafs.GetListenerPayloadPaths(lis.Name, false, true)
	if err != nil {
		return err
	}
	if len(payloads) == 0 {
		return fmt.Errorf("payloads not found")
	}

	// As needed, delete a specific payload.
	payloads = append(payloads, "Cancel")
	label := fmt.Sprintf("Payloads hosted on %s", lis.Name)
	res, err := stdin.Select(label, payloads)
	if err != nil {
		return err
	}
	if res == "Cancel" {
		return fmt.Errorf("canceled")
	}

	isDelete, err := stdin.Confirm(fmt.Sprintf("Delete '%s'?", res))
	if err != nil {
		return err
	}
	if isDelete {
		payloadsDir, err := metafs.GetListenerPayloadsDir(lis.Name, false)
		if err != nil {
			return err
		}
		err = os.RemoveAll(fmt.Sprintf("%s/%s", payloadsDir, res))
		if err != nil {
			return err
		}
		stdout.LogSuccess("Payload deleted.")
	} else {
		stdout.LogWarn("Canceled")
	}

	return nil
}

func HandleListenerList(serverState *state.ServerState) error {
	liss, err := serverState.DB.ListenerGetAll()
	if err != nil {
		return err
	}

	listener.PrintListeners(liss)
	return nil
}

func HandlePayloadGen(serverState *state.ServerState) error {
	// Get listeners for generating a payload from listener settings
	liss, err := serverState.DB.ListenerGetAll()
	if err != nil {
		return err
	}
	stdout.PrintBannerPayload()
	payloadType := wizard.WizardPayloadType()

	if strings.HasPrefix(payloadType, "implant") {
		imp, err := wizard.WizardPayloadImplantGenerate(
			meta.GetSpecificHost(serverState.Conf.Host),
			liss,
			payloadType,
		)
		if err != nil {
			return err
		}

		fmt.Println()
		spin := stdout.NewSpinner("Generating an implant...")
		spin.Start()

		_, outFile, err := imp.Generate(serverState)
		if err != nil {
			spin.Stop()
			return err
		}

		spin.Stop()
		stdout.LogSuccess(fmt.Sprintf("Implant saved at %s", color.HiGreenString(outFile)))
	} else if strings.HasPrefix(payloadType, "stager") {
		stg, err := wizard.WizardPayloadStagerGenerate(
			meta.GetSpecificHost(serverState.Conf.Host),
			liss,
			payloadType,
		)
		if err != nil {
			return err
		}

		fmt.Println()
		spin := stdout.NewSpinner("Generating a stager...")
		spin.Start()

		_, outFile, err := stg.Generate(serverState)
		if err != nil {
			spin.Stop()
			return err
		}

		spin.Stop()
		stdout.LogSuccess(fmt.Sprintf("Stager saved at %s", color.HiGreenString(outFile)))
	} else if strings.HasPrefix(payloadType, "shellcode") {
		shc, err := wizard.WizardPayloadShellcodeGenerate(
			meta.GetSpecificHost(serverState.Conf.Host),
			liss,
			payloadType,
		)
		if err != nil {
			return err
		}

		fmt.Println()
		spin := stdout.NewSpinner("Generating a shellcode...")
		spin.Start()

		_, outFile, err := shc.Generate(serverState)
		if err != nil {
			spin.Stop()
			return err
		}

		spin.Stop()
		stdout.LogSuccess(fmt.Sprintf("Shellcode saved at %s", color.HiGreenString(outFile)))
	} else {
		return fmt.Errorf("invalid payload type")
	}

	return nil
}

func HandleAgentUseById(line string, argStartIdx int, serverState *state.ServerState) error {
	agentId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	ag, err := serverState.DB.AgentGetById(agentId)
	if err != nil {
		return fmt.Errorf("agent not found: %v", err)
	}

	// Set agent status
	serverState.AgentMode.Uuid = ag.Uuid
	serverState.AgentMode.Name = ag.Name

	stdout.LogSuccess("Switched to agent mode.")
	return nil
}

func HandleAgentDeleteById(line string, argStartIdx int, serverState *state.ServerState) error {
	agentId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	// Check if the agent exists
	ag, err := serverState.DB.AgentGetById(agentId)
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
	err = serverState.DB.AgentDeleteById(agentId)
	if err != nil {
		return err
	}

	// Delete the related folder
	lootAgentDir, err := metafs.GetAgentLootDir(ag.Name, false)
	if err != nil {
		return err
	}
	err = os.RemoveAll(lootAgentDir)
	if err != nil {
		return err
	}

	stdout.LogSuccess("Agent deleted.")
	return nil
}

func HandleAgentInfoById(line string, argStartIdx int, serverState *state.ServerState) error {
	agentId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	ag, err := serverState.DB.AgentGetById(agentId)
	if err != nil {
		return fmt.Errorf("agent not found: %v", err)
	}

	agent.PrintAgents([]*agent.Agent{ag})
	return nil
}

func HandleAgentList(serverState *state.ServerState) error {
	ags, err := serverState.DB.AgentGetAll()
	if err != nil {
		return err
	}

	agent.PrintAgents(ags)
	return nil
}

// **AGENT MODE**
// "Am" means Agent Mode
func HandleAmExit(serverState *state.ServerState) {
	// Go back to the root mode
	serverState.AgentMode = state.AgentMode{}
}

func HandleAmAgentInfo(serverState *state.ServerState) error {
	ag, err := serverState.DB.AgentGetByUuid(serverState.AgentMode.Uuid)
	if err != nil {
		return fmt.Errorf("agent not found: %v", err)
	}

	agent.PrintAgents([]*agent.Agent{ag})
	return nil
}

func HandleAmTaskSet(line string, serverState *state.ServerState) error {
	// Set a task into the task list file
	err := task.SetTask(line, serverState.AgentMode.Name)
	if err != nil {
		return err
	}

	stdout.LogSuccess("Task set successfully.")
	return nil
}

func HandleAmTaskClean(serverState *state.ServerState) error {
	res, err := stdin.Confirm("Are you sure you want to delete all tasks?")
	if err != nil {
		return err
	}
	if !res {
		return fmt.Errorf("canceled")
	}

	err = metafs.DeleteAllAgentTasks(serverState.AgentMode.Name, false)
	if err != nil {
		return err
	}

	stdout.LogSuccess("All tasks deleted successfully.")
	return nil
}

func HandleAmTaskList(serverState *state.ServerState) error {
	tasks, err := metafs.ReadAgentTasks(serverState.AgentMode.Name, false)
	if err != nil {
		return err
	}
	if len(tasks) == 0 {
		return fmt.Errorf("task not set")
	}

	stdout.LogSuccess("Task List")
	for _, task := range tasks {
		fmt.Println(task)
	}

	return nil
}

func HandleAmLoot(serverState *state.ServerState) error {
	allLoot, err := loot.GetAllLoot(serverState.AgentMode.Name)
	if err != nil {
		return err
	}
	stdout.LogSuccess("\n")
	fmt.Println(allLoot)
	return nil
}

func HandleAmLootClean(serverState *state.ServerState) error {
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
	return nil
}
