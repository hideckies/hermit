package task

import (
	"fmt"
	"strings"

	"github.com/hideckies/hermit/pkg/common/stdin"
)

func SetTaskRunAs(task string) (string, error) {
	taskSplit := strings.Split(task, " ")
	if len(taskSplit) < 3 {
		return "", fmt.Errorf("not enough argument")
	}

	cmd := taskSplit[0]
	user := taskSplit[1]
	program := strings.Join(taskSplit[2:], " ")

	// Set password
	password, err := stdin.ReadPassword(fmt.Sprintf("Enter %s's password", user))
	if err != nil {
		return "", err
	}

	task = cmd + " " + user + " " + password + " " + program
	return task, nil
}
