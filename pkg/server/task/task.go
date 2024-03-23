package task

import (
	"fmt"
	"strings"

	"github.com/hideckies/hermit/pkg/common/stdin"
)

func AdjustTask(task string) (string, error) {
	// Adjust arguments
	var err error

	switch {
	case strings.HasPrefix(task, "cp "), strings.HasPrefix(task, "download "),
		strings.HasPrefix(task, "mv "), strings.HasPrefix(task, "upload "):

		task, err = SetTaskWithSrcDest(task)
		if err != nil {
			return "", err
		}
	case strings.HasPrefix(task, "dll ") || strings.HasPrefix(task, "shellcode "):
		task, err = SetTaskPidSrc(task)
		if err != nil {
			return "", err
		}
	case task == "kill":
		yes, err := stdin.Confirm("Do you want to terminate the implant?")
		if err != nil {
			return "", err
		}
		if !yes {
			return "", fmt.Errorf("canceld")
		}
	case task == "ls":
		task = "ls ."
	case strings.HasPrefix(task, "reg "):
		task, err = SetTaskReg(task)
		if err != nil {
			return "", err
		}
	case strings.HasPrefix(task, "runas "):
		task, err = SetTaskRunAs(task)
		if err != nil {
			return "", err
		}
	case strings.HasPrefix(task, "token "):
		task, err = SetTaskToken(task)
		if err != nil {
			return "", err
		}
	default:
	}

	return task, nil
}
