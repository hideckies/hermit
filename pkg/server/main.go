package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/google/uuid"

	"github.com/hideckies/hermit/pkg/common/certs"
	"github.com/hideckies/hermit/pkg/common/config"
	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/server/console"
	"github.com/hideckies/hermit/pkg/server/db"
	"github.com/hideckies/hermit/pkg/server/job"
	"github.com/hideckies/hermit/pkg/server/operator"
	"github.com/hideckies/hermit/pkg/server/rpc"
	"github.com/hideckies/hermit/pkg/server/state"
)

type Context struct {
	Debug bool
}

type ServerCmd struct {
	ConfigPath string `short:"c" help:"Specify the config file path. Hermit priority this configuration"`
}

func run(configPath string) error {
	stdout.PrintBanner()

	// Set a log file
	logFile, err := meta.OpenLogFile(false)
	if err != nil {
		return err
	}
	defer logFile.Close()

	// Read a server config
	serverConfig, err := config.ReadServerConfigJson(configPath, false)
	if err != nil {
		return err
	}

	// Initialize a database instance
	database, err := db.NewDatabase()
	if err != nil {
		return err
	}
	defer database.DB.Close()

	// Initialize a job
	j := job.NewJob()

	// Initialize a server state
	serverState, err := state.NewServerState(serverConfig, database, j)
	if err != nil {
		return err
	}

	// Generate certificates for RPC server
	if err := certs.RPCGenerateCertificates(serverState.Conf); err != nil {
		return err
	}

	// Register admin to database
	ope := operator.NewOperator(0, uuid.NewString(), "admin")
	err = database.OperatorAdd(ope)
	if err != nil {
		return err
	}

	// go j.Run()
	go rpc.Run(serverState)
	go console.Readline(serverState, ope.Uuid)

	signal.Notify(j.ChQuit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-j.ChQuit

	// Set 'inactive' all listeners on database
	errUpdate := database.ListenerUpdateActiveAll(false)
	// Delete all connected operators from database
	errDelete := database.OperatorDeleteAll()
	if errUpdate != nil {
		return errUpdate
	}
	if errDelete != nil {
		return errDelete
	}
	stdout.LogSuccess("Bye.")
	return nil
}

func (s *ServerCmd) Run(ctx *Context) error {
	if err := run(s.ConfigPath); err != nil {
		stdout.LogFailed(fmt.Sprint(err))
		os.Exit(1)
	}
	return nil
}

type VersionCmd struct{}

func (v *VersionCmd) Run(ctx *Context) error {
	meta.PrintVersion()
	return nil
}

var cli struct {
	Debug bool `help:"Enable debug mode."`

	Server  ServerCmd  `cmd:"" default:"withargs" help:"Start C2 server and console"`
	Version VersionCmd `cmd:"" help:"Print the version of Hermit"`
}

func main() {
	if err := meta.MakeAppDirs(false); err != nil {
		stdout.LogFailed(fmt.Sprint(err))
		os.Exit(1)
	}

	ctx := kong.Parse(
		&cli,
		kong.Name("hermit"),
		kong.Description("Hermit C2 Server & Console"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: false,
		}))

	err := ctx.Run(&Context{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}
