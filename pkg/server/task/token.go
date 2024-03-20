package task

import (
	"strings"

	"github.com/hideckies/hermit/pkg/common/stdin"
)

func SetTaskToken(task string) (string, error) {
	if strings.HasPrefix(task, "token steal ") {
		label := "What do you do with stolen token?"
		items := []string{
			"Create a new process",
			"Login as another user",
		}
		res, err := stdin.Select(label, items)
		if err != nil {
			return "", err
		}

		if strings.HasPrefix(res, "Create") {
			// Create a new process
			procName, err := stdin.ReadInput("Specify Process", "notepad.exe")
			if err != nil {
				return "", err
			}
			task = task + " " + procName
		} else if strings.HasPrefix(res, "Login") {
			// Login as another user
			task = task + " " + "login"
		}
	}

	return task, nil
}
