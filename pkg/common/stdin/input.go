package stdin

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ReadInput(label string, defaultValue string) (string, error) {
	if defaultValue == "" {
		fmt.Printf("%s: ", label)
	} else {
		fmt.Printf("%s [default: %s]: ", label, defaultValue)
	}

	reader := bufio.NewReader(os.Stdin)

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	line = strings.TrimSuffix(line, "\n")
	if line == "" {
		line = defaultValue
	}

	return line, nil
}

func Confirm(label string) (bool, error) {
	res, err := ReadInput(fmt.Sprintf("%s [y/n]", label), "")
	if err != nil {
		return false, err
	}

	answer := strings.TrimSuffix(res, "\n")
	answer = strings.ToLower(answer)

	if answer == "y" || answer == "yes" {
		return true, nil
	} else if answer == "n" || answer == "no" {
		return false, nil
	} else {
		return false, fmt.Errorf("please input \"yes\" or \"no\"")
	}
}
