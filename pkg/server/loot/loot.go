package loot

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/common/meta"
)

func GetAllLoot(agentName string) (string, error) {
	taskResults, err := meta.ReadAllTaskResults(agentName, false)
	if err != nil {
		return "", err
	}
	if len(taskResults) == 0 {
		return "", fmt.Errorf("loot not found")
	}

	allLoot := ""
	for _, taskResult := range taskResults {
		allLoot += taskResult
		allLoot += "\n\n-----------------------------------------\n\n"
	}
	return allLoot, nil
}
