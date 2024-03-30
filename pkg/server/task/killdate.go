package task

import (
	"fmt"
	"strings"

	"github.com/hideckies/hermit/pkg/common/meta"
)

func SetTaskKillDate(task string) (string, error) {
	taskSplit := strings.Split(task, " ")
	if len(taskSplit) != 3 {
		return "", fmt.Errorf("invalid arguments")
	}

	command := taskSplit[0]
	killdate := strings.Join(taskSplit[1:], " ")

	killDateInt, err := meta.ParseDateTimeInt(killdate)
	if err != nil {
		return "", err
	}
	killDateUint := uint(killDateInt)

	task = command + " " + fmt.Sprint(killDateUint)
	return task, nil
}
