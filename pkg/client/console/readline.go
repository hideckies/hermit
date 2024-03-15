package console

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"

	"github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/protobuf/rpcpb"
)

func Readline(
	c rpcpb.HermitRPCClient,
	ctx context.Context,
	clientState *state.ClientState,
) error {
	ri, err := stdin.InitReadline(true, "/tmp/readline_client.tmp")
	if err != nil {
		stdout.LogFailed(fmt.Sprint(err))
		os.Exit(1)
	}
	defer ri.Close()
	ri.CaptureExitSignal()

	for {
		// Make prompt
		var p string
		if clientState.AgentMode.Name == "" {
			p = stdin.MakePrompt("client", "")
		} else {
			p = stdin.MakePrompt("client", clientState.AgentMode.Name)
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

		if clientState.AgentMode.Name == "" {

			// **ROOT MODE**

			switch {

			// COMMON
			case line == "help", line == "?":
				HandleHelp(ri, false)
			case line == "version":
				if err := HandleVersion(c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case line == "exit", line == "quit":
				goto exit

			// OPERATOR
			case line == "operator whoami":
				HandleOperatorWhoami(clientState)
			case strings.HasPrefix(line, "operator info "):
				if err := HandleOperatorInfoById(line, 14, clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case line == "operator list", line == "operators":
				if err := HandleOperatorList(clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}

			// LISTENER
			case line == "listener start":
				if err := HandleListenerStart(clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case strings.HasPrefix(line, "listener start "):
				if err := HandleListenerStartById(line, 14, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case strings.HasPrefix(line, "listener stop "):
				if err := HandleListenerStopById(line, 14, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case strings.HasPrefix(line, "listener delete "):
				if err := HandleListenerDeleteById(line, 16, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case strings.HasPrefix(line, "listener info "):
				if err := HandleListenerInfoById(line, 14, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case strings.HasPrefix(line, "listener payloads "):
				if err := HandleListenerPayloadsById(line, 18, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case line == "listener list", line == "listeners":
				if err := HandleListenerList(c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}

			// PAYLOAD
			case line == "payload gen":
				if err := HandlePayloadGen(clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}

			// AGENT
			case strings.HasPrefix(line, "agent use "):
				if err := HandleAgentUseById(line, 10, clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case strings.HasPrefix(line, "agent delete "):
				if err := HandleAgentDeleteById(line, 13); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case strings.HasPrefix(line, "agent info "):
				if err := HandleAgentInfoById(line, 11, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case line == "agent list", line == "agents":
				if err := HandleAgentList(c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}

			// MISC
			case line == "":
			default:
				HandleInvalidCommand(line)
			}

		} else {

			// **AGENT MODE**

			switch {

			// COMMON
			case line == "help", line == "?":
				HandleHelp(ri, true)
			case line == "version":
				if err := HandleVersion(c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case line == "exit", line == "quit":
				HandleAmExit(clientState)

			// AGENT
			case line == "agent info":
				if err := HandleAmAgentInfo(clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}

			// TASK
			case
				strings.HasPrefix(line, "cat "),
				strings.HasPrefix(line, "cd "),
				strings.HasPrefix(line, "cp "),
				strings.HasPrefix(line, "download "),
				strings.HasPrefix(line, "keylog "),
				line == "ls", strings.HasPrefix(line, "ls "),
				strings.HasPrefix(line, "mkdir"),
				line == "pwd",
				strings.HasPrefix(line, "rm "),
				strings.HasPrefix(line, "rmdir "),
				line == "screenshot",
				strings.HasPrefix(line, "shell "),
				strings.HasPrefix(line, "sleep "),
				strings.HasPrefix(line, "upload "),
				line == "whoami":
				if err := HandleAmTaskSetByAgentName(line, clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case line == "task clean":
				if err := HandleAmTaskCleanByAgentName(clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case line == "task list", line == "tasks":
				if err := HandleAmTaskListByAgentName(clientState, c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}

			// LOOT
			case line == "loot":
				if err := HandleAmLoot(c, ctx); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}
			case line == "loot clean":
				if err := HandleAmLootClean(); err != nil {
					stdout.LogFailed(fmt.Sprint(err))
				}

			// MISC
			case line == "":
			default:
				HandleInvalidCommand(line)
			}
		}
	}

exit:
	return nil
}
