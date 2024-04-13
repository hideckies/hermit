package stdin

import (
	"fmt"
	"os"

	"github.com/chzyer/readline"
	"github.com/hideckies/hermit/pkg/common/stdout"
)

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
		Prompt:      prompt,
		HistoryFile: historyFile,
		// AutoComplete: completer,
		// InterruptPrompt: "^C",
		// EOFPrompt: "exit",

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
	stdout.LogInfo("Run 'help', '?', or 'help <command>' for the usage.\n\n")

	return ri, nil
}
