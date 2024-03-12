package stdin

import (
	"fmt"

	"github.com/fatih/color"
)

func MakePrompt(prefix string, suffix string) string {
	if prefix != "" {
		prefix = "[" + color.HiCyanString(prefix) + "] "
	}
	if suffix != "" {
		suffix = " [" + color.HiRedString(suffix) + "]"
	}
	return fmt.Sprintf("%s > ", fmt.Sprintf(
		"%s%s%s",
		prefix,
		color.HiYellowString("Hermit"),
		suffix,
	))
}

func MakeShellPrompt(user string, host string, directory string) string {
	return fmt.Sprintf(
		"%s%s%s%s%s%s ",
		color.CyanString(user),
		color.CyanString("@"),
		color.CyanString(host),
		color.RedString(":"),
		color.HiGreenString(directory),
		color.RedString("$"),
	)
}
