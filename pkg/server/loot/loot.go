package loot

import (
	"fmt"
	"strings"

	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
)

func GetAllLoot(agentName string, filter string) (string, error) {
	allLoot, err := metafs.ReadAllAgentLoot(agentName, false)
	if err != nil {
		return "", err
	}
	if len(allLoot) == 0 {
		return "", fmt.Errorf("loot not found")
	}

	contents := ""
	for _, _loot := range allLoot {
		if filter == "" {
			contents += _loot + "\n"
		} else {
			if strings.Contains(_loot, filter) {
				contents += _loot + "\n"
			}
		}
	}
	return contents, nil
}
