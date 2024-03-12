package meta

import (
	"bufio"
	"fmt"
	"os/exec"
)

func ExecCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(stderr)
	errorText := ""
	for scanner.Scan() {
		errorText = errorText + "\n" + scanner.Text()
	}
	if errorText != "" {
		return "", fmt.Errorf(errorText)
	}

	return "Success", nil
}
