package task

import (
	"strings"

	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
)

func SetTask(task string, agentName string) error {
	// Adjust arguments
	var err error

	switch {
	case strings.HasPrefix(task, "cp "), strings.HasPrefix(task, "download "),
		strings.HasPrefix(task, "mv "), strings.HasPrefix(task, "upload "):

		task, err = SetTaskWithSrcDest(task)
		if err != nil {
			return err
		}
	case task == "ls":
		task = "ls ."
	case strings.HasPrefix(task, "reg "):
		task, err = SetTaskReg(task)
		if err != nil {
			return err
		}
	case strings.HasPrefix(task, "token "):
		task, err = SetTaskToken(task)
		if err != nil {
			return err
		}
	default:
	}

	// Add the task to the '.tasks' file
	err = metafs.WriteAgentTask(agentName, task, false)
	if err != nil {
		return err
	}
	return nil
}
