package console

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/chzyer/readline"

	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/server/state"
)

func handleCommand(
	ri *readline.Instance,
	serverState *state.ServerState,
	line string,
	isAgentMode bool,
	adminUuid string,
) (isContinue bool) {
	isContinue = true

	switch {

	// COMMON
	case line == "help", line == "?":
		HandleHelp(ri, isAgentMode)
	case line == "version":
		HandleVersion()
	case line == "exit", line == "quit":
		if !isAgentMode {
			isContinue = false
		} else {
			HandleAmExit(serverState)
		}

	// CONFIG
	case !isAgentMode && line == "client-config gen":
		if err := HandleClientConfigGen(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}

	// OPERATOR
	case line == "operator whoami":
		HandleOperatorWhoami()
	case strings.HasPrefix(line, "operator info "):
		if err := HandleOperatorInfoById(line, 14, serverState, adminUuid); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case line == "operator list", line == "operators":
		HandleOperatorList(serverState, adminUuid)

	// LISTENER
	case line == "listener start":
		if err := HandleListenerStart(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case strings.HasPrefix(line, "listener start "):
		if err := HandleListenerStartById(line, 15, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case strings.HasPrefix(line, "listener stop "):
		if err := HandleListenerStopById(line, 14, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case strings.HasPrefix(line, "listener delete "):
		if err := HandleListenerDeleteById(line, 15, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case strings.HasPrefix(line, "listener info "):
		if err := HandleListenerInfoById(line, 14, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case strings.HasPrefix(line, "listener payloads "):
		if err := HandleListenerPayloadsById(line, 18, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case line == "listener list", line == "listeners":
		if err := HandleListenerList(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}

	// PAYLOAD
	case !isAgentMode && line == "payload gen":
		if err := HandlePayloadGen(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}

	// AGENT
	case !isAgentMode && strings.HasPrefix(line, "agent use "):
		if err := HandleAgentUseById(line, 10, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case !isAgentMode && strings.HasPrefix(line, "agent delete "):
		if err := HandleAgentDeleteById(line, 13, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case !isAgentMode && strings.HasPrefix(line, "agent info "):
		if err := HandleAgentInfoById(line, 11, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case !isAgentMode && (line == "agent list" || line == "agents"):
		if err := HandleAgentList(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case isAgentMode && line == "agent info":
		if err := HandleAmAgentInfo(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}

	// TASK
	case
		isAgentMode && (strings.HasPrefix(line, "cat ") ||
			strings.HasPrefix(line, "cd ") ||
			strings.HasPrefix(line, "cp ") ||
			strings.HasPrefix(line, "download ") ||
			strings.HasPrefix(line, "keylog ") ||
			line == "ls" || strings.HasPrefix(line, "ls ") ||
			strings.HasPrefix(line, "mkdir") ||
			line == "pwd" ||
			strings.HasPrefix(line, "rm ") ||
			strings.HasPrefix(line, "rmdir ") ||
			line == "screenshot" ||
			strings.HasPrefix(line, "shell ") ||
			strings.HasPrefix(line, "sleep ") ||
			strings.HasPrefix(line, "upload ") ||
			line == "whoami"):
		if err := HandleAmTaskSet(line, serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case isAgentMode && line == "task clean":
		if err := HandleAmTaskClean(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case isAgentMode && (line == "task list" || line == "tasks"):
		if err := HandleAmTaskList(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}

	// LOOT
	case isAgentMode && line == "loot":
		if err := HandleAmLoot(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}
	case isAgentMode && line == "loot clean":
		if err := HandleAmLootClean(serverState); err != nil {
			stdout.LogFailed(fmt.Sprint(err))
		}

	// MISC
	case line == "":
	default:
		HandleInvalidCommand(line)
	}
	return isContinue

}

func Readline(serverState *state.ServerState, adminUuid string) {
	// Wait for the RPC server starts to avoid the prompt displays before the "C2 server started" message.
	<-serverState.Job.ChServerStarted

	ri, err := stdin.InitReadline(false, "/tmp/readline.tmp")
	if err != nil {
		stdout.LogFailed(fmt.Sprint(err))
		os.Exit(1)
	}
	defer ri.Close()
	ri.CaptureExitSignal()

	isAgentMode := false
	isContinue := true

	for {
		isAgentMode = serverState.AgentMode.Name != ""

		// Make prompt
		var p string
		if !isAgentMode {
			p = stdin.MakePrompt("", "")
		} else {
			p = stdin.MakePrompt("", serverState.AgentMode.Name)
		}
		ri.SetPrompt(p)

		line, err := ri.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		// Remove redundant spaces
		line = utils.StandardizeSpaces(line)

		isContinue = handleCommand(ri, serverState, line, isAgentMode, adminUuid)
		if !isContinue {
			break
		}
	}

	serverState.Job.ChQuit <- syscall.SIGINT
	return
}
