package console

import (
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"

	"github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/parser"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	servState "github.com/hideckies/hermit/pkg/server/state"
)

func Readline(clientState *state.ClientState) error {
	ri, err := stdin.InitReadline(true, "/tmp/readline_client.tmp")
	if err != nil {
		stdout.LogFailed(fmt.Sprint(err))
		os.Exit(1)
	}
	defer ri.Close()
	ri.CaptureExitSignal()

	isAgentMode := false
	var currentParser *kong.Kong

	for {
		isAgentMode = clientState.AgentMode.Name != ""

		// Make prompt
		var p string
		if !isAgentMode {
			p = stdin.MakePrompt("client", "")
		} else {
			p = stdin.MakePrompt("client", clientState.AgentMode.Name)
		}
		ri.SetPrompt(p)

		// Set parser
		if isAgentMode {
			currentParser, err = parser.NewParser(
				&parser.GrammarAgentMode{},
				clientState.Conf.Server.Host,
				clientState.Conf.Server.Domains,
			)
			if err != nil {
				stdout.LogFailed(fmt.Sprintf("Parse Error: %s"))
				break
			}
		} else {
			currentParser, err = parser.NewParser(
				&parser.GrammarRoot{},
				clientState.Conf.Server.Host,
				clientState.Conf.Server.Domains,
			)
			if err != nil {
				stdout.LogFailed(fmt.Sprintf("Parse Error: %s"))
				break
			}
		}
		clientState.Parser = currentParser

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

		ctx, err := clientState.Parser.Parse(args)
		if err != nil {
			if err, ok := err.(*kong.ParseError); ok {
				stdout.LogFailed(err.Error())
			}
			continue
		}

		err = ctx.Run(ctx, &servState.ServerState{}, clientState)
		if err != nil {
			stdout.LogFailed(fmt.Sprint(err))
			continue
		}

		if !clientState.Continue {
			break
		}
	}
	return nil
}
