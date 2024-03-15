package loot

import (
	"fmt"

	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
)

func GetAllLoot(agentName string) (string, error) {
	allLoot, err := metafs.ReadAllAgentLoot(agentName, false)
	if err != nil {
		return "", err
	}
	if len(allLoot) == 0 {
		return "", fmt.Errorf("loot not found")
	}

	contents := ""
	for _, _loot := range allLoot {
		contents += _loot + "\n"
	}
	return contents, nil
}
