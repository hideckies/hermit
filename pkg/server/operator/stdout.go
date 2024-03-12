package operator

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/common/stdout"
)

func PrintOperators(ops []*Operator, currentUuid string) {
	if len(ops) == 0 {
		stdout.LogWarn("There are no operators.")
		return
	}

	tHead := []string{"ID", "NAME"}
	tRows := [][]string{}
	for _, op := range ops {
		id := fmt.Sprint(op.Id)
		if op.Uuid == currentUuid {
			id = fmt.Sprintf("*%d", op.Id)
		}
		tRows = append(tRows, []string{id, op.Name})
	}

	stdout.LogSuccess("")
	stdout.PrintTable(tHead, tRows)
	fmt.Println()
}
