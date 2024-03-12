package console

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/fatih/color"

	"github.com/hideckies/hermit/pkg/client/rpc"
	"github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/common/wizard"
	"github.com/hideckies/hermit/pkg/protobuf/rpcpb"
	"github.com/hideckies/hermit/pkg/server/agent"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/operator"
)

func Readline(
	c rpcpb.HermitRPCClient,
	ctx context.Context,
	clientState *state.ClientState,
) error {
	defaultPrompt := stdin.MakePrompt("client", "")
	historyFile := "/tmp/readline_client.tmp"
	l, err := stdin.NewReadlineInstance(defaultPrompt, historyFile)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	l.CaptureExitSignal()

	stdout.LogInfo("The console starts.")
	stdout.LogInfo("Run `help` or `?` for the usage.\n\n")

	for {
		// Make prompt
		var p string
		if clientState.AgentMode.Name == "" {
			p = stdin.MakePrompt("client", "")
		} else {
			p = stdin.MakePrompt("client", clientState.AgentMode.Name)
		}
		l.SetPrompt(p)

		line, err := l.Readline()
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
				stdin.ConsoleUsage(l.Stderr(), true, clientState.AgentMode.Name != "")
			case line == "version":
				res, err := rpc.RequestGetVersion(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprintf("%v", err))
					continue
				}
				stdout.LogSuccess(res)
			case line == "exit", line == "quit":
				goto exit
			// OPERATOR
			case line == "operator whoami":
				stdout.LogSuccess(clientState.Conf.Operator)
			case strings.HasPrefix(line, "operator info "):
				operatorId, err := stdin.ParseArgUint(line, 14)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}

				op, err := rpc.RequestOperatorGetById(c, ctx, uint(operatorId))
				if err != nil {
					stdout.LogFailed(fmt.Sprintf("%v", err))
					continue
				}
				operator.PrintOperators([]*operator.Operator{op}, clientState.Conf.Uuid)
			case line == "operator list", line == "operators":
				ops, err := rpc.RequestOperatorGetAll(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprintf("%v", err))
					continue
				}
				operator.PrintOperators(ops, clientState.Conf.Uuid)
			// LISTENER
			case line == "listener start":
				lis, err := wizard.WizardListenerStart(
					meta.GetSpecificHost(clientState.Conf.Server.Host), clientState.Conf.Server.Domains)
				if err != nil {
					stdout.LogFailed(fmt.Sprintf("%s", err))
					continue
				}
				res, err := rpc.RequestListenerStart(c, ctx, lis)
				if err != nil {
					stdout.LogFailed(fmt.Sprintf("%s", err))
					continue
				}
				stdout.LogSuccess(res)
			case strings.HasPrefix(line, "listener start "):
				listenerId, err := stdin.ParseArgUint(line, 14)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				res, err := rpc.RequestListenerStartById(c, ctx, listenerId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess(res)
			case strings.HasPrefix(line, "listener stop "):
				listenerId, err := stdin.ParseArgUint(line, 14)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				res, err := rpc.RequestListenerStopById(c, ctx, listenerId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess(res)
			case strings.HasPrefix(line, "listener delete "):
				listenerId, err := stdin.ParseArgUint(line, 16)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				res, err := rpc.RequestListenerDeleteById(c, ctx, listenerId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess(res)
			case strings.HasPrefix(line, "listener info "):
				listenerId, err := stdin.ParseArgUint(line, 14)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				lis, err := rpc.RequestListenerGetById(c, ctx, uint(listenerId))
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				listener.PrintListeners([]*listener.Listener{lis})
			case strings.HasPrefix(line, "listener payloads "):
				listenerId, err := stdin.ParseArgUint(line, 18)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				// TODO
				fmt.Printf("Not implemented yet: %s\n", listenerId)
			case line == "listener list", line == "listeners":
				listeners, err := rpc.RequestListenerGetAll(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				listener.PrintListeners(listeners)
			// PAYLOAD
			case line == "payload gen":
				// Get listeners for generating a payload from listener settings
				liss, err := rpc.RequestListenerGetAll(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.PrintBannerPayload()
				payloadType := wizard.WizardPayloadType()
				if strings.HasPrefix(payloadType, "implant") {
					imp, err := wizard.WizardPayloadImplantGenerate(
						meta.GetSpecificHost(clientState.Conf.Server.Host), liss, payloadType)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}

					spin := stdout.NewSpinner("Generating a payload...")
					spin.Start()
					data, err := rpc.RequestPayloadImplantGenerate(c, ctx, imp)
					if err != nil {
						stdout.LogFailed(fmt.Sprintf("%s", err))
						continue
					}
					spin.Stop()

					// Save the executable
					appDir, err := meta.GetAppDir()
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					payloadsDir := fmt.Sprintf("%s/payloads", appDir)
					outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, imp.Name, imp.Format)

					err = os.WriteFile(outFile, data, 0755)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					stdout.LogSuccess(fmt.Sprintf("Stager saved at %s", color.HiGreenString(outFile)))
				} else if strings.HasPrefix(payloadType, "stager") {
					stg, err := wizard.WizardPayloadStagerGenerate(
						meta.GetSpecificHost(clientState.Conf.Server.Host),
						liss,
						payloadType,
					)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}

					spin := stdout.NewSpinner("Generating a payload...")
					spin.Start()
					data, err := rpc.RequestPayloadStagerGenerate(c, ctx, stg)
					if err != nil {
						stdout.LogFailed(fmt.Sprintf("%s", err))
						continue
					}
					spin.Stop()

					// Save the executable
					appDir, err := meta.GetAppDir()
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					payloadsDir := fmt.Sprintf("%s/payloads", appDir)
					outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, stg.Name, stg.Format)

					err = os.WriteFile(outFile, data, 0755)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					stdout.LogSuccess(fmt.Sprintf("Stager saved at %s", color.HiGreenString(outFile)))
				} else if strings.HasPrefix(payloadType, "shellcode") {
					shc, err := wizard.WizardPayloadShellcodeGenerate(
						meta.GetSpecificHost(clientState.Conf.Server.Host),
						liss,
						payloadType,
					)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}

					spin := stdout.NewSpinner("Generating a shellcode...")
					spin.Start()
					data, err := rpc.RequestPayloadShellcodeGenerate(c, ctx, shc)
					if err != nil {
						stdout.LogFailed(fmt.Sprintf("%s", err))
						continue
					}
					spin.Stop()

					// Save the shellcode
					appDir, err := meta.GetAppDir()
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					payloadsDir := fmt.Sprintf("%s/payloads", appDir)
					outFile := fmt.Sprintf("%s/%s.%s", payloadsDir, shc.Name, shc.Format)

					err = os.WriteFile(outFile, data, 0755)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					stdout.LogSuccess(fmt.Sprintf("Shellcode saved at %s", color.HiGreenString(outFile)))
				} else {
					stdout.LogFailed("Invalid paylaod type.")
				}
			// AGENT
			case strings.HasPrefix(line, "agent use "):
				agentId, err := stdin.ParseArgUint(line, 10)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				ag, err := rpc.RequestAgentGetById(c, ctx, agentId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				clientState.AgentMode.Uuid = ag.Uuid
				clientState.AgentMode.Name = ag.Name
				clientState.AgentMode.CWD = ""
			case strings.HasPrefix(line, "agent delete "):
				agentId, err := stdin.ParseArgUint(line, 13)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				fmt.Printf("Delete agent %d", agentId)
				// TODO
				// ...
			case strings.HasPrefix(line, "agent info "):
				agentId, err := stdin.ParseArgUint(line, 11)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				ag, err := rpc.RequestAgentGetById(c, ctx, agentId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				agent.PrintAgents([]*agent.Agent{ag})
			case line == "agent list", line == "agents":
				ags, err := rpc.RequestAgentGetAll(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				agent.PrintAgents(ags)
			// MISC
			case line == "":
			default:
				stdout.LogFailed(fmt.Sprintf("Invalid command: '%s'", line))
			}
		} else {
			// **AGENT MODE**
			switch {
			// COMMON
			case line == "help", line == "?":
				stdin.ConsoleUsage(l.Stderr(), true, clientState.AgentMode.Name != "")
			case line == "version":
				res, err := rpc.RequestGetVersion(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess(res)
			case line == "exit", line == "quit":
				// Go back to the root mode
				clientState.AgentMode = state.AgentMode{}
			// AGENT
			case line == "agent info":
				ags, err := rpc.RequestAgentGetAll(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				var targetAgent *agent.Agent
				for _, ag := range ags {
					if ag.Uuid == clientState.AgentMode.Uuid {
						targetAgent = ag
						break
					}
				}
				if targetAgent == nil {
					stdout.LogFailed("agent not found")
					continue
				}
				stdout.LogSuccess("")
				agent.PrintAgents([]*agent.Agent{targetAgent})
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
				// Send request to the server for setting a task
				err := rpc.RequestTaskSet(c, ctx, line)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogInfo("Request to set task.")
			case line == "task clean":
				res, err := stdin.Confirm("Are you sure you want to delete all tasks?")
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if !res {
					stdout.LogWarn("Canceled.")
					continue
				}
				err = rpc.RequestTaskClean(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("All tasks deleted successfully.")
			case line == "task list", line == "tasks":
				taskList, err := rpc.RequestTaskList(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("")
				fmt.Println(taskList)
			// LOOT
			case line == "loot":
				allLoot, err := rpc.RequestLootGetAll(c, ctx)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("")
				fmt.Println(allLoot)
			case line == "loot clean":
				_, err := stdin.Confirm("Are you sure you want to clean all loot gained?")
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("All loot deleted successfully.")
			// MISC
			case line == "":
			default:
				stdout.LogFailed(fmt.Sprintf("Invalid command: '%s'", line))
			}
		}
	}

exit:
	return nil
}
