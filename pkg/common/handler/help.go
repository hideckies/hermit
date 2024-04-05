package handler

import (
	"fmt"

	"github.com/alecthomas/kong"
)

func HandleHelp(realCtx *kong.Context, command []string) error {
	ctx, err := kong.Trace(realCtx.Kong, command)
	if err != nil {
		return err
	}
	if ctx.Error != nil {
		return ctx.Error
	}
	err = ctx.PrintUsage(false)
	if err != nil {
		return err
	}
	fmt.Fprintln(realCtx.Stdout)
	return nil
}
