package task

import (
	"fmt"
	"strconv"

	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/server/service"
)

func SetTaskRportfwdAdd(task string) (string, error) {
	lport, err := stdin.ReadInput("Local Port", "8080")
	if err != nil {
		return "", err
	}

	rip, err := stdin.ReadInput("Remote IP", "0.0.0.0")
	if err != nil {
		return "", err
	}

	rport, err := stdin.ReadInput("Remote Port", "8000")
	if err != nil {
		return "", err
	}

	task = task + " " + lport + " " + rip + " " + rport

	// Display the input
	items := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("Local port to listen", lport),
		stdout.NewSingleTableItem("Remote ip/port to forward", fmt.Sprintf("%s:%s", rip, rport)),
	}
	stdout.PrintSingleTable("Reverse Port Forwarding Options", items)

	yes, err := stdin.Confirm("It's okay to send the task with the above options?")
	if err != nil {
		return "", err
	}
	if !yes {
		return "", fmt.Errorf("canceld")
	}

	// Start listener for SSH server
	lport64, err := strconv.ParseUint(lport, 10, 64)
	if err != nil {
		return "", err
	}
	lport16 := uint16(lport64)

	rport64, err := strconv.ParseUint(rport, 10, 64)
	if err != nil {
		return "", err
	}
	rport16 := uint16(rport64)

	go service.RTunnelListenerStart("127.0.0.1", lport16, rip, rport16)

	task = "Not implemented yet."

	return task, nil
}

func SetTaskRportfwdRm(task string) (string, error) {
	task = "Not implemented yet."
	return task, nil
}
