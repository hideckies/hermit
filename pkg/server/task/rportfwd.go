package task

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
)

func SetTaskRportfwdAdd(task string) (string, error) {
	lIP, err := stdin.ReadInput("Local IP to bind", "0.0.0.0")
	if err != nil {
		return "", err
	}

	lPort, err := stdin.ReadInput("Local Port to bind", "8080")
	if err != nil {
		return "", err
	}

	fwIP, err := stdin.ReadInput("Remote IP to forward", "0.0.0.0")
	if err != nil {
		return "", err
	}

	fwPort, err := stdin.ReadInput("Remote Port to forward", "8000")
	if err != nil {
		return "", err
	}

	task = task + " " + lIP + " " + lPort + " " + fwIP + " " + fwPort

	// Display the input
	items := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("Bind IP", lIP),
		stdout.NewSingleTableItem("Bind Port", lPort),
		stdout.NewSingleTableItem("Forward IP", fwIP),
		stdout.NewSingleTableItem("Forward Port", fwPort),
	}
	stdout.PrintSingleTable("Reverse Port Forwarding Options", items)

	yes, err := stdin.Confirm("It's okay to send the task with the above options?")
	if err != nil {
		return "", err
	}
	if !yes {
		return "", fmt.Errorf("canceld")
	}

	return task, nil
}

func SetTaskRportfwdRm(task string) (string, error) {
	task = "Not implemented yet."
	return task, nil
}
