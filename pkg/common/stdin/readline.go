package stdin

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
	"github.com/hideckies/hermit/pkg/common/stdout"
)

var completer = readline.NewPrefixCompleter(
	// Common
	readline.PcItem("help"),
	readline.PcItem("?"),
	readline.PcItem("version"),
	// readline.PcItem("log"), Read log file with a pager.
	readline.PcItem("exit"),
	readline.PcItem("quit"),

	// CONFIG
	readline.PcItem("client-config gen"),

	// OPERATOR
	readline.PcItem("operator whoami"),
	readline.PcItem("operator info"),
	readline.PcItem("operator list"),
	readline.PcItem("operators"),

	// ATTACK FLOW
	// readline.PcItem("attackflow gen"),
	// readline.PcItem("attackflow info"),
	// readline.PcItem("attackflow list"),
	// readline.PcItem("attackflows"),

	// LISTENER
	readline.PcItem("listener start"),
	readline.PcItem("listener stop"),
	readline.PcItem("listener delete"),
	readline.PcItem("listener info"),
	readline.PcItem("listener payloads"),
	readline.PcItem("listener list"),
	readline.PcItem("listeners"),

	// PAYLOAD
	readline.PcItem("payload gen"),

	// AGENT
	readline.PcItem("agent use"),
	readline.PcItem("agent delete"),
	readline.PcItem("agent info"),
	readline.PcItem("agent list"),
	readline.PcItem("agents"),

	// **AGENT MODE**
	// AGENT
	readline.PcItem("agent info"),

	// TASK
	readline.PcItem("cat"),
	readline.PcItem("cd"),
	// readline.PcItem("checkin"),
	readline.PcItem("cp"),
	readline.PcItem("download"),
	readline.PcItem("execute"),
	// readline.PcItem("dll"), DLL spawn and inject modules
	// readline.PcItem("find"),
	// readline.PcItem("history"), Retrieve history data of each application
	// readline.PcItem("inline-exec"),
	// readline.PcItem("ipconfig"),
	readline.PcItem("keylog"),
	readline.PcItem("kill"),
	readline.PcItem("ls"),
	readline.PcItem("migrate"),
	readline.PcItem("mkdir"),
	readline.PcItem("mv"),
	// readline.PcItem("net"),
	// readline.PcItem("pivot"),
	// readline.PcItem("portfwd"),
	// readline.PcItem("powershell"),
	// readline.PcItem("procdump"), Dump process memory with MiniDumpWriteDump function
	readline.PcItem("ps"),
	// readline.PcItem("psexec"),
	readline.PcItem("pwd"),
	// readline.PcItem("reg"), Registry key
	readline.PcItem("rm"),
	readline.PcItem("rmdir"),
	// readline.PcItem("runas"), Start the process as a specified user.
	readline.PcItem("screenshot"),
	// readline.PcItem("shellcode"),
	readline.PcItem("sleep"),
	// readline.PcItem("socks"), SOCKS proxy
	// readline.PcItem("sysinfo"),
	// readline.PcItem("task"),
	// readline.PcItem("token"), Token manipulation
	readline.PcItem("upload"),
	// readline.PcItem("webcam"),
	readline.PcItem("whoami"),

	readline.PcItem("task clean"),
	readline.PcItem("task list"),
	readline.PcItem("tasks"),

	// LOOT
	readline.PcItem("loot"),
	readline.PcItem("loot clean"),
)

func ConsoleUsage(w io.Writer, isClient bool, isAgentMode bool) {
	io.WriteString(w, "\n")

	io.WriteString(w, "COMMON\n")
	io.WriteString(w, "======\n\n")
	io.WriteString(w, "  help, ?                : Print the usage\n")
	io.WriteString(w, "  version                : Print the version of Hermit\n")
	io.WriteString(w, "  exit, quit             : Exit the console and stop the program\n")
	io.WriteString(w, "\n")

	if !isClient {
		io.WriteString(w, "CONFIG\n")
		io.WriteString(w, "======\n\n")
		io.WriteString(w, "  client-config gen      :  Generate a config file for the C2 client\n")
		io.WriteString(w, "\n")
	}

	io.WriteString(w, "OPERATOR\n")
	io.WriteString(w, "========\n\n")
	io.WriteString(w, "  operator whoami        : Print the current operator name\n")
	io.WriteString(w, "  operator info <ID>     : Print a operator info with a specific ID\n")
	io.WriteString(w, "  operator list          : List operators\n")
	io.WriteString(w, "  operators              : Alias for 'operator list'\n")
	io.WriteString(w, "\n")

	io.WriteString(w, "LISTENER\n")
	io.WriteString(w, "========\n\n")
	io.WriteString(w, "  listener start         : Start a listener\n")
	io.WriteString(w, "  listener start    <ID> : Start a listener with a specific ID\n")
	io.WriteString(w, "  listener stop     <ID> : Stop a listener with a specific ID\n")
	io.WriteString(w, "  listener delete   <ID> : Delete a listener with a specific ID\n")
	io.WriteString(w, "  listener info     <ID> : Print a listener info with a specific ID\n")
	io.WriteString(w, "  listener payloads <ID> : List/Delete payloads hosted on the listener\n")
	io.WriteString(w, "  listener list          : List running listeners\n")
	io.WriteString(w, "  listeners              : Alias for 'listener list'\n")
	io.WriteString(w, "\n")

	if !isAgentMode {
		io.WriteString(w, "PAYLOAD\n")
		io.WriteString(w, "=======\n\n")
		io.WriteString(w, "  payload gen            : Generate a payload\n")
		io.WriteString(w, "\n")

		io.WriteString(w, "AGENT\n")
		io.WriteString(w, "=====\n\n")
		io.WriteString(w, "  agent use    <ID>      : Switch to the agent mode with a specific ID\n")
		io.WriteString(w, "  agent delete <ID>      : Delete an agent with a specific ID\n")
		io.WriteString(w, "  agent info   <ID>      : Print an agent info with a specific ID\n")
		io.WriteString(w, "  agent list             : List agents\n")
		io.WriteString(w, "  agents                 : List agents. Alias for 'agent list'\n")
		io.WriteString(w, "\n")
	} else {
		io.WriteString(w, "AGENT\n")
		io.WriteString(w, "=====\n\n")
		io.WriteString(w, "  agent info             : Print the agent information\n")
		io.WriteString(w, "\n")

		io.WriteString(w, "TASK\n")
		io.WriteString(w, "====\n\n")
		io.WriteString(w, "  cat      <FILE>        : Print the contents of a file\n")
		io.WriteString(w, "  cd       <DIR>         : Change the working directory\n")
		io.WriteString(w, "  cp       <SRC> <DEST>  : Copy a file\n")
		io.WriteString(w, "  download <SRC> <DEST>  : Download a file from the target computer\n")
		io.WriteString(w, "  execute  <CMD>         : Execute a system command on target computer\n")
		io.WriteString(w, "  keylog   <NUM>         : Keylogging for N seconds\n")
		io.WriteString(w, "  kill                   : Stop the implant process\n")
		io.WriteString(w, "  ls       <DIR>         : List files in a directory\n")
		io.WriteString(w, "  migrate  <PID>         : Get into another process\n")
		io.WriteString(w, "  mkdir    <DIR>         : Create a new directory\n")
		io.WriteString(w, "  mv       <SRC> <DEST>  : Move a file to a destination location\n")
		io.WriteString(w, "  ps                     : List processes that are running\n")
		io.WriteString(w, "  ps kill  <PID>         : Kill a specified process\n")
		io.WriteString(w, "  pwd                    : Print the current working directory\n")
		io.WriteString(w, "  rm       <FILE>        : Remove a file\n")
		io.WriteString(w, "  rmdir    <DIR>         : Remove a directory\n")
		io.WriteString(w, "  screenshot             : Take a screenshot on target computer\n")
		io.WriteString(w, "  sleep    <NUM>         : Set sleep time (seconds) between requests from beacon\n")
		io.WriteString(w, "  upload   <SRC> <DEST>  : Upload a file to the target computer\n")
		io.WriteString(w, "  whoami                 : Print the current username\n")
		io.WriteString(w, "\n")
		io.WriteString(w, "  task clean             : Remove all tasks from waitlist\n")
		io.WriteString(w, "  task list              : List tasks waiting for the results\n")
		io.WriteString(w, "  tasks                  : Alias for 'task list'\n")
		io.WriteString(w, "\n")

		io.WriteString(w, "LOOT\n")
		io.WriteString(w, "====\n\n")
		io.WriteString(w, "  loot                   : List all loot gained from target computer\n")
		io.WriteString(w, "  loot clean             : Remove all loot\n")
		io.WriteString(w, "\n")
	}
}

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func newReadlineInstance(prompt string, historyFile string) (*readline.Instance, error) {
	return readline.NewEx(&readline.Config{
		Prompt:          prompt,
		HistoryFile:     historyFile,
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",

		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})
}

func InitReadline(isClient bool, historyFile string) (*readline.Instance, error) {
	defaultPrompt := MakePrompt("", "")
	if isClient {
		defaultPrompt = MakePrompt("client", "")
	}

	ri, err := newReadlineInstance(defaultPrompt, historyFile)
	if err != nil {
		stdout.LogFailed(fmt.Sprint(err))
		os.Exit(1)
	}

	stdout.LogInfo("The console starts.")
	stdout.LogInfo("Run `help` or `?` for the usage.\n\n")

	return ri, nil
}

func ParseArgUint(command string, argStartIndex int) (uint, error) {
	arg := strings.TrimSpace(command[argStartIndex:])
	if len(arg) == 0 {
		return 0, fmt.Errorf("not enough argument. specify the operator ID")
	}

	parsed, err := strconv.ParseUint(arg, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid operator ID: %v", err)
	}
	return uint(parsed), nil
}

func ParseArgString(command string, argStartIndex int) (string, error) {
	arg := strings.TrimSpace(command[argStartIndex:])
	if len(arg) == 0 {
		return "", fmt.Errorf("not enough argument")
	}
	return arg, nil
}
