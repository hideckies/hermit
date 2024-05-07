package parser

import (
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/utils"
)

type GrammarGeneral struct {
	// COMMON
	Help    helpCmd    `cmd:"" aliases:"?" help:"Print the usage for each command." group:"COMMON:"`
	Version versionCmd `cmd:"" help:"Print the version of Hermit." group:"COMMON:"`
	// Log     logCmd     `cmd:"" help:"Manage logs." group:"COMMON:"`
	// Broadcast bloadcastCmd `cmd:"" help:"Broadcast messages to other operators." group:"COMMON:"`

	// OPERATOR
	Operator  operatorCmd     `cmd:"" help:"Manage operators." group:"OPERATOR:"`
	Operators operatorListCmd `cmd:"" help:"Alias for 'agent list'." group:"OPERATOR:"`

	// LISTENER
	Listener  listenerCmd     `cmd:"" help:"Manage listeners." group:"LISTENER:"`
	Listeners listenerListCmd `cmd:"" help:"Alias for 'listener list'." group:"LISTENER:"`

	// PAYLOAD
	Payload payloadCmd `cmd:"" help:"Manage payloads." group:"PAYLOAD:"`
}

type GrammarRoot struct {
	GrammarGeneral

	// COMMON
	Exit exitCmd `cmd:"" aliases:"quit" help:"Exit the console." group:"COMMON:"`

	// CONFIG
	ClientConfig clientConfigCmd `cmd:"" help:"Manage client config." group:"CONFIG:"`

	// AGENT
	Agent  agentCmd     `cmd:"" help:"Manage agents." group:"AGENT:"`
	Agents agentListCmd `cmd:"" help:"Alias for 'agent list'." group:"AGENT:"`
}

type GrammarAgentMode struct {
	GrammarGeneral

	// COMMON
	Exit amExitCmd `cmd:"" aliases:"quit" help:"Exit the agent mode." group:"COMMON:"`

	// AGENT
	Agent amAgentCmd `cmd:"" help:"Manage agents." group:"AGENT:"`

	// TASK
	Assembly amTaskAssemblyCmd `cmd:"" help:"Load and execute .NET assembly." group:"TASK:"`
	Cat      amTaskCatCmd      `cmd:"" help:"Read contents of a file." group:"TASK:"`
	Cd       amTaskCdCmd       `cmd:"" help:"Change the working directory." group:"TASK:"`
	// CheckIn    amTaskCheckInCmd    `cmd:"" help:"Check-in" group:"TASK:"`
	Cmd      amTaskCmdCmd      `cmd:"" help:"Execute arbitrary system command." group:"TASK:"`
	Connect  amTaskConnectCmd  `cmd:"" help:"Change listener URL to connect." group:"TASK:"`
	Cp       amTaskCpCmd       `cmd:"" help:"Copy a file." group:"TASK:"`
	Creds    amTaskCredsCmd    `cmd:"" help:"Credentials." group:"TASK:"`
	Dll      amTaskDllCmd      `cmd:"" help:"Load DLL and inject modules into the specified process." group:"TASK:"`
	Download amTaskDownloadCmd `cmd:"" help:"Download a file." group:"TASK:"`
	Env      amTaskEnvCmd      `cmd:"" help:"Manage environment variables." group:"TASK:"`
	Envs     amTaskEnvLsCmd    `cmd:"" help:"alias for 'env ls'" group:"TASK:"`
	// Find       amTaskFindCmd       `cmd:"" help:"Find files." group:"TASK:"`
	Group    amTaskGroupCmd    `cmd:"" help:"Manage groups." group:"TASK:"`
	Groups   amTaskGroupLsCmd  `cmd:"" help:"Alias for 'group ls'." group:"TASK:"`
	History  amTaskHistoryCmd  `cmd:"" help:"Retrieve information from history files of applications" group:"TASK:"`
	Ip       amTaskIpCmd       `cmd:"" help:"Print the network interface information on target computer" group:"TASK:"`
	Jitter   amTaskJitterCmd   `cmd:"" help:"Set jitter time (seconds) between requests from beacon" group:"TASK:"`
	Keylog   amTaskKeylogCmd   `cmd:"" help:"Keylogging N seconds." group:"TASK:"`
	Kill     amTaskKillCmd     `cmd:"" help:"Terminate the current process." group:"TASK:"`
	Killdate amTaskKilldateCmd `cmd:"" help:"Change killdate (UTC) for the implant beacon." group:"TASK:"`
	Ls       amTaskLsCmd       `cmd:"" help:"List files in a directory." group:"TASK:"`
	Migrate  amTaskMigrateCmd  `cmd:"" help:"Migrate the implant into another process." group:"TASK:"`
	Mkdir    amTaskMkdirCmd    `cmd:"" help:"Create a new directory." group:"TASK:"`
	Mv       amTaskMvCmd       `cmd:"" help:"Move a file to a destination location." group:"TASK:"`
	Net      amTaskNetCmd      `cmd:"" help:"Get TCP connections." group:"TASK:"`
	// Nslookup   amTaskNslookupCmd   `cmd:"" help:"Manage network." group:"TASK:"`
	Pe      amTaskPeCmd      `cmd:"" help:"Load and execute PE (Portable Executable) file." group:"TASK:"`
	Persist amTaskPersistCmd `cmd:"" help:"Establish persistence for implant." group:"TASK:"`
	// Pivot amTaskPivotCmd `cmd:"" help:"Manage pivoting" group:"TASK:"`
	// PowerShell amTaskPowerShellCmd `cmd:"" help:"Execute PowerShell command." group:"TASK:"`
	Procdump amTaskProcdumpCmd `cmd:"" help:"Dump process memory to a specified output file." group:"TASK:"`
	Ps       amTaskPsCmd       `cmd:"" help:"Manage processes." group:"TASK:"`
	// PsExec     amTaskPsExecCmd     `cmd:"Manage processes with psexec." help:"" group:"TASK:"`
	Pwd        amTaskPwdCmd        `cmd:"" help:"Print the current working directory." group:"TASK:"`
	Reg        amTaskRegCmd        `cmd:"" help:"Manage registry." group:"TASK:"`
	Rm         amTaskRmCmd         `cmd:"" help:"Remove a file." group:"TASK:"`
	Rmdir      amTaskRmdirCmd      `cmd:"" help:"Remove a directory." group:"TASK:"`
	Rportfwd   amTaskRportfwdCmd   `cmd:"" help:"Manage reverse port forwarding." group:"TASK:"`
	Runas      amTaskRunasCmd      `cmd:"" help:"Execute a program as another user." group:"TASK:"`
	Screenshot amTaskScreenshotCmd `cmd:"" help:"Take a screenshot on target computer." group:"TASK:"`
	Shellcode  amTaskShellcodeCmd  `cmd:"" help:"Inject shellcode into the specified process." group:"TASK:"`
	Sleep      amTaskSleepCmd      `cmd:"" help:"Set sleep time (seconds) between requests from beacon." group:"TASK:"`
	// Socks      amTaskSocksCmd      `cmd:"" help:"" group:"TASK:"`
	// Sysinfo amTaskSysinfoCmd `cmd:"" help:"Print system information." group:"TASK:"`
	Token  amTaskTokenCmd  `cmd:"" help:"Manage tokens." group:"TASK:"`
	Upload amTaskUploadCmd `cmd:"" help:"Upload a file to the target computer." group:"TASK:"`
	User   amTaskUserCmd   `cmd:"" help:"Manage users." group:"TASK:"`
	Users  amTaskUserLsCmd `cmd:"" help:"Alias for 'user ls'." group:"TASK:"`
	// WebCam amTaskWebCamCmd   `cmd:"" help:"WebCam" group:"TASK:"`
	Whoami amTaskWhoamiCmd `cmd:"" help:"Print the current user information." group:"TASK:"`

	Task  amTaskCmd     `cmd:"" help:"Manage tasks." group:"TASK MANAGE:"`
	Tasks amTaskListCmd `cmd:"" help:"Alias for 'task list'." group:"TASK MANAGE:"`

	// LOOT
	Loot amLootCmd `cmd:"" help:"Manage loot. We can see task results with this command." group:"LOOT:"`
}

func NewParser(grammar interface{}, addr string, domains []string) (*kong.Kong, error) {
	parser, err := kong.New(
		grammar,
		kong.Name(""),
		kong.Description(""),
		kong.Writers(os.Stdout, os.Stdout),
		kong.Exit(func(int) {}),
		kong.ConfigureHelp(kong.HelpOptions{
			NoAppSummary:        true,
			Summary:             false,
			Compact:             true,
			FlagsLast:           false,
			NoExpandSubcommands: false,
		}),
		kong.NoDefaultHelp(),
		kong.Vars{
			"default_bind_addr": meta.GetSpecificHost(addr),
			"default_bind_port": fmt.Sprint(utils.GenerateRandomPort()),
			"default_domains":   strings.Join(domains, ","),
		},
	)
	if err != nil {
		return nil, err
	}

	return parser, err
}
