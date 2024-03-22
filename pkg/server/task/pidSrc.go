package task

import (
	"fmt"
	"strings"
)

func SetTaskPidSrc(task string) (string, error) {
	taskSplit := strings.Split(task, " ")
	if len(taskSplit) != 3 {
		return "", fmt.Errorf("invalid arguments")
	}

	command := taskSplit[0]
	pid := taskSplit[1]
	src := taskSplit[2]
	task = command + " " + pid + " " + src

	return task, nil
}
