package meta

import (
	"bufio"
	"os/exec"
)

func ExecCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(stderr)
	outText := ""
	for scanner.Scan() {
		outText = outText + "\n" + scanner.Text()
	}

	return outText, nil
}
