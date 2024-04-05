package console

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/chzyer/readline"
	shellwords "github.com/mattn/go-shellwords"

	cliState "github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/parser"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/server/state"
)

func Readline(serverState *state.ServerState) {
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
	var currentParser *kong.Kong

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

		// Set parser
		if isAgentMode {
			currentParser, err = parser.NewParser(
				&parser.GrammarAgentMode{},
				serverState.Conf.Host,
				serverState.Conf.Domains,
			)
			if err != nil {
				stdout.LogFailed(fmt.Sprintf("Parse Error: %s", err))
				break
			}
		} else {
			currentParser, err = parser.NewParser(
				&parser.GrammarRoot{},
				serverState.Conf.Host,
				serverState.Conf.Domains,
			)
			if err != nil {
				stdout.LogFailed(fmt.Sprintf("Parse Error: %s", err))
				break
			}
		}
		serverState.Parser = currentParser

		// Read input
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

		args, err := shellwords.Parse(line)
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}

		ctx, err := serverState.Parser.Parse(args)
		if err != nil {
			if err, ok := err.(*kong.ParseError); ok {
				stdout.LogFailed(err.Error())
				stdout.LogInfo("Run 'help <command>' for usage.")
			}
			continue
		}

		err = ctx.Run(ctx, serverState, &cliState.ClientState{})
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}

		if !serverState.Continue {
			break
		}
	}

	serverState.Job.ChQuit <- syscall.SIGINT
}
