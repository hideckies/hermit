package stdin

import (
	"fmt"
	"strings"

	"github.com/manifoldco/promptui"
)

func Select(label string, items []string) (string, error) {
	selector := promptui.Select{
		Label:        label,
		Items:        items,
		Size:         len(items),
		HideHelp:     true,
		HideSelected: true,
	}

	_, result, err := selector.Run()
	if err != nil {
		return "", err
	}

	result = strings.TrimSuffix(result, "\n")

	fmt.Printf("%s: %s\n", label, result)

	return result, nil
}
