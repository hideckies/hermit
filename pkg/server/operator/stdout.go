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

	tHead := []string{"ID", "Name", "Login"}
	tRows := [][]string{}
	for _, op := range ops {
		id := fmt.Sprint(op.Id)
		if op.Uuid == currentUuid {
			id = fmt.Sprintf("*%d", op.Id)
		}
		tRows = append(tRows, []string{id, op.Name, op.Login})
	}

	stdout.LogSuccess("")
	stdout.PrintTable(tHead, tRows)
	fmt.Println()
}

func PrintOperatorDetails(op *Operator) {
	items := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("ID", fmt.Sprint(op.Id)),
		stdout.NewSingleTableItem("Name", op.Name),
		stdout.NewSingleTableItem("UUID", op.Uuid),
		stdout.NewSingleTableItem("Login", op.Login),
	}

	stdout.LogSuccess("")
	stdout.PrintSingleTable("OPERATOR", items)
}
