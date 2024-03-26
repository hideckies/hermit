package console

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/hideckies/hermit/pkg/client/rpc"
	"github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/wizard"
	"github.com/hideckies/hermit/pkg/protobuf/rpcpb"
	"github.com/hideckies/hermit/pkg/server/agent"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/operator"
	"github.com/hideckies/hermit/pkg/server/task"
)

func HandleInvalidCommand(line string) {
	stdout.LogFailed(fmt.Sprintf("Invalid command: `%s`", line))
}

func HandleHelp(ri *readline.Instance, isAgentMode bool) {
	stdin.ConsoleUsage(ri.Stderr(), true, isAgentMode)
}

func HandleVersion(c rpcpb.HermitRPCClient, ctx context.Context) error {
	res, err := rpc.RequestGetVersion(c, ctx)
	if err != nil {
		return err
	}

	stdout.LogSuccess(res)
	return nil
}

func HandleOperatorWhoami(clientState *state.ClientState) {
	stdout.LogSuccess(clientState.Conf.Operator)
}

func HandleOperatorInfoById(
	line string,
	argStartIdx int,
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	operatorId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	op, err := rpc.RequestOperatorGetById(c, ctx, uint(operatorId))
	if err != nil {
		return fmt.Errorf("operator not found: %v", err)
	}

	operator.PrintOperatorDetails(op)
	return nil
}

func HandleOperatorList(
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	ops, err := rpc.RequestOperatorGetAll(c, ctx)
	if err != nil {
		return err
	}

	operator.PrintOperators(ops, clientState.Conf.Uuid)
	return nil
}

func HandleListenerStart(
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	lis, err := wizard.WizardListenerStart(
		meta.GetSpecificHost(clientState.Conf.Server.Host), clientState.Conf.Server.Domains)
	if err != nil {
		return err
	}

	res, err := rpc.RequestListenerStart(c, ctx, lis)
	if err != nil {
		return err
	}

	stdout.LogSuccess(res)
	return nil
}

func HandleListenerStartById(
	line string,
	argStartIdx int,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	res, err := rpc.RequestListenerStartById(c, ctx, listenerId)
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}

	stdout.LogSuccess(res)
	return nil
}

func HandleListenerStopById(
	line string,
	argStartIdx int,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	res, err := rpc.RequestListenerStopById(c, ctx, listenerId)
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}

	stdout.LogSuccess(res)
	return nil
}

func HandleListenerDeleteById(
	line string,
	argStartIdx int,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	res, err := rpc.RequestListenerDeleteById(c, ctx, listenerId)
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}

	stdout.LogSuccess(res)
	return nil
}

func HandleListenerInfoById(
	line string,
	argStartIdx int,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	lis, err := rpc.RequestListenerGetById(c, ctx, uint(listenerId))
	if err != nil {
		return fmt.Errorf("listener not found: %v", err)
	}

	listener.PrintListenerDetails(lis)
	return nil
}

func HandleListenerPayloadsById(
	line string,
	argStartIdx int,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	listenerId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	lis, err := rpc.RequestListenerGetById(c, ctx, listenerId)
	if err != nil {
		return err
	}

	payloads, err := rpc.RequestListenerPayloadsById(c, ctx, uint(listenerId))
	if err != nil {
		return fmt.Errorf("listener payloads not found: %v", err)
	}

	payloadsSplit := strings.Split(payloads, "\n")

	// As needed, delete a specific payload.
	payloadsSplit = append(payloadsSplit, "Cancel")
	label := fmt.Sprintf("Payloads hosted on %s", lis.Name)
	res, err := stdin.Select(label, payloadsSplit)
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
		// Request to delete a payload.
		_, err := rpc.RequestListenerPayloadsDeleteById(c, ctx, uint(listenerId), res)
		if err != nil {
			return err
		}
		stdout.LogSuccess("Payload deleted.")
	} else {
		stdout.LogWarn("Canceled")
	}

	return nil
}

func HandleListenerList(c rpcpb.HermitRPCClient, ctx context.Context) error {
	listeners, err := rpc.RequestListenerGetAll(c, ctx)
	if err != nil {
		return err
	}

	listener.PrintListeners(listeners)
	return nil
}

func HandlePayloadGen(
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	// Get listeners for generating a payload from listener settings
	liss, err := rpc.RequestListenerGetAll(c, ctx)
	if err != nil {
		return err
	}

	stdout.PrintBannerPayload()

	payloadType := wizard.WizardPayloadType()

	if strings.HasPrefix(payloadType, "implant") {
		imp, err := wizard.WizardPayloadImplantGenerate(
			meta.GetSpecificHost(clientState.Conf.Server.Host), liss, payloadType)
		if err != nil {
			return err
		}

		spin := stdout.NewSpinner("Generating a payload...")
		spin.Start()
		data, err := rpc.RequestPayloadImplantGenerate(c, ctx, imp)
		if err != nil {
			spin.Stop()
			return err
		}
		spin.Stop()

		// Save the executable
		appDir, err := metafs.GetAppDir()
		if err != nil {
			return err
		}
		payloadsDir := fmt.Sprintf("%s/client/payloads", appDir)
		outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, imp.Name, imp.Format)

		err = os.WriteFile(outFile, data, 0755)
		if err != nil {
			return err
		}

		stdout.LogSuccess(fmt.Sprintf("Implant saved at %s", color.HiGreenString(outFile)))
	} else if strings.HasPrefix(payloadType, "stager") {
		stg, err := wizard.WizardPayloadStagerGenerate(
			meta.GetSpecificHost(clientState.Conf.Server.Host),
			liss,
			payloadType,
		)
		if err != nil {
			return err
		}

		spin := stdout.NewSpinner("Generating a payload...")
		spin.Start()
		data, err := rpc.RequestPayloadStagerGenerate(c, ctx, stg)
		if err != nil {
			spin.Stop()
			return err
		}
		spin.Stop()

		// Save the executable
		appDir, err := metafs.GetAppDir()
		if err != nil {
			return err
		}
		payloadsDir := fmt.Sprintf("%s/client/payloads", appDir)
		outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, stg.Name, stg.Format)

		err = os.WriteFile(outFile, data, 0755)
		if err != nil {
			return err
		}

		stdout.LogSuccess(fmt.Sprintf("Stager saved at %s", color.HiGreenString(outFile)))
	} else if strings.HasPrefix(payloadType, "shellcode") {
		shc, err := wizard.WizardPayloadShellcodeGenerate(
			meta.GetSpecificHost(clientState.Conf.Server.Host),
			liss,
			payloadType,
		)
		if err != nil {
			return err
		}

		spin := stdout.NewSpinner("Generating a shellcode...")
		spin.Start()
		data, err := rpc.RequestPayloadShellcodeGenerate(c, ctx, shc)
		if err != nil {
			spin.Stop()
			return err
		}
		spin.Stop()

		// Save the shellcode
		appDir, err := metafs.GetAppDir()
		if err != nil {
			return err
		}
		payloadsDir := fmt.Sprintf("%s/client/payloads", appDir)
		outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, shc.Name, shc.Format)

		err = os.WriteFile(outFile, data, 0755)
		if err != nil {
			return err
		}
		stdout.LogSuccess(fmt.Sprintf("Shellcode saved at %s", color.HiGreenString(outFile)))
	} else {
		stdout.LogFailed("Invalid paylaod type.")
	}

	return nil
}

func HandleAgentUseById(
	line string,
	argStartIdx int,
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	agentId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	ag, err := rpc.RequestAgentGetById(c, ctx, agentId)
	if err != nil {
		return fmt.Errorf("agent not found: %v", err)
	}

	clientState.AgentMode.Uuid = ag.Uuid
	clientState.AgentMode.Name = ag.Name
	clientState.AgentMode.CWD = ""
	return nil
}

func HandleAgentDeleteById(
	line string,
	argStartIdx int,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	res, err := stdin.Confirm("Are you sure you want to delete the agent?")
	if err != nil {
		return err
	}
	if !res {
		return fmt.Errorf("canceled")
	}

	agentId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	err = rpc.RequestAgentDeleteById(c, ctx, agentId)
	if err != nil {
		return err
	}

	stdout.LogSuccess("Agent deleted.")
	return nil
}

func HandleAgentInfoById(
	line string,
	argStartIdx int,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	agentId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	ag, err := rpc.RequestAgentGetById(c, ctx, agentId)
	if err != nil {
		return fmt.Errorf("agent not found: %v", err)
	}

	agent.PrintAgentDetails(ag)
	return nil
}

func HandleAgentNoteById(
	line string,
	argStartIdx int,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	agentId, err := stdin.ParseArgUint(line, argStartIdx)
	if err != nil {
		return err
	}

	ag, err := rpc.RequestAgentGetById(c, ctx, agentId)
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

	return nil
}

func HandleAgentList(c rpcpb.HermitRPCClient, ctx context.Context) error {
	ags, err := rpc.RequestAgentGetAll(c, ctx)
	if err != nil {
		return err
	}

	agent.PrintAgents(ags)
	return nil
}

// **AGENT MODE**
// Am means Agent Mode
func HandleAmExit(clientState *state.ClientState) {
	// Go back to the root mode
	clientState.AgentMode = state.AgentMode{}
}

func HandleAmAgentInfo(
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	ags, err := rpc.RequestAgentGetAll(c, ctx)
	if err != nil {
		return err
	}

	var targetAgent *agent.Agent
	for _, ag := range ags {
		if ag.Uuid == clientState.AgentMode.Uuid {
			targetAgent = ag
			break
		}
	}
	if targetAgent == nil {
		return fmt.Errorf("agent not found")
	}

	stdout.LogSuccess("")
	agent.PrintAgentDetails(targetAgent)
	return nil
}

func HandleAmAgentNote(
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	ags, err := rpc.RequestAgentGetAll(c, ctx)
	if err != nil {
		return err
	}

	var targetAgent *agent.Agent
	for _, ag := range ags {
		if ag.Uuid == clientState.AgentMode.Uuid {
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

	return nil
}

func HandleAmTaskSetByAgentName(
	line string,
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	task, err := task.AdjustTask(line)
	if err != nil {
		return err
	}

	// Send request to the server for setting a task
	err = rpc.RequestTaskSetByAgentName(c, ctx, task, clientState.AgentMode.Name)
	if err != nil {
		return err
	}

	stdout.LogInfo("Request to set task.")
	return nil
}

func HandleAmTaskClearByAgentName(
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	res, err := stdin.Confirm("Are you sure you want to delete all tasks?")
	if err != nil {
		return err
	}
	if !res {
		return fmt.Errorf("canceled")
	}

	err = rpc.RequestTaskClearByAgentName(c, ctx, clientState.AgentMode.Name)
	if err != nil {
		return err
	}

	stdout.LogSuccess("All tasks deleted successfully.")
	return nil
}

func HandleAmTaskListByAgentName(
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	taskList, err := rpc.RequestTaskListByAgentName(c, ctx, clientState.AgentMode.Name)
	if err != nil {
		return err
	}

	stdout.LogSuccess("")
	fmt.Println(taskList)
	return nil
}

func HandleAmLoot(
	clientState *state.ClientState,
	c rpcpb.HermitRPCClient,
	ctx context.Context,
) error {
	allLoot, err := rpc.RequestLootGetAll(c, ctx, clientState.AgentMode.Name)
	if err != nil {
		return err
	}

	stdout.LogSuccess("\n")
	fmt.Println(allLoot)
	return nil
}

func HandleAmLootClear() error {
	_, err := stdin.Confirm("Are you sure you want to delete all loot gained?")
	if err != nil {
		return err
	}

	stdout.LogSuccess("All loot deleted successfully.")
	return nil
}
