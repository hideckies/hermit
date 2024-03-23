package metafs

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hideckies/hermit/pkg/common/meta"
)

func GetAgentsDir(isClient bool) (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	if isClient {
		return fmt.Sprintf("%s/client/agents", appDir), nil
	} else {
		return fmt.Sprintf("%s/server/agents", appDir), nil
	}
}

func GetAgentDir(agentName string, isClient bool) (string, error) {
	agentsDir, err := GetAgentsDir(isClient)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", agentsDir, agentName), nil
}

func GetAgentLootDir(agentName string, isClient bool) (string, error) {
	agentDir, err := GetAgentDir(agentName, isClient)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/loot", agentDir), nil
}

func GetAgentNoteFile(agentName string, isClient bool) (string, error) {
	agentDir, err := GetAgentDir(agentName, isClient)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%s/note", agentDir), nil
}

func GetAgentTasksFile(agentName string, isClient bool) (string, error) {
	agentDir, err := GetAgentDir(agentName, isClient)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%s/.tasks", agentDir), nil
}

func MakeAgentChildDirs(agentName string, isClient bool) error {
	agentDir, err := GetAgentDir(agentName, isClient)
	if err != nil {
		return err
	}

	err = os.MkdirAll(agentDir+"/loot/procdumps", PERM)
	if err != nil {
		return err
	}
	err = os.MkdirAll(agentDir+"/loot/screenshots", PERM)
	if err != nil {
		return err
	}

	// Create 'note' file
	noteFile, err := os.Create(fmt.Sprintf("%s/note", agentDir))
	if err != nil {
		return err
	}
	noteFile.Close()

	// Create '.tasks' file under 'tasks' folder
	tasksFile := agentDir + "/.tasks"
	if _, err := os.Stat(tasksFile); err != nil {
		newFile, err := os.Create(tasksFile)
		if err != nil {
			return err
		}
		newFile.Close()
	}

	return nil
}

func WriteAgentTask(
	agentName string,
	taskName string,
	isClient bool,
) error {
	tasksFile, err := GetAgentTasksFile(agentName, isClient)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(tasksFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(taskName + "\n"); err != nil {
		return err
	}

	return nil
}

func ReadAgentTasks(agentName string, isClient bool) ([]string, error) {
	tasksFile, err := GetAgentTasksFile(agentName, isClient)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(tasksFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tasks := []string{}

	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		tasks = append(tasks, fileScanner.Text())
	}

	return tasks, nil
}

func DeleteAgentTask(agentName string, taskName string, isClient bool) error {
	tasksFile, err := GetAgentTasksFile(agentName, isClient)
	if err != nil {
		return err
	}

	f, err := os.Open(tasksFile)
	if err != nil {
		return err
	}

	updatedTasks := []string{}
	deleted := false

	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		task := fileScanner.Text()
		if !deleted && task == taskName {
			deleted = true
			continue
		}
		updatedTasks = append(updatedTasks, task)
	}
	f.Close()

	// Overwrite task list
	f, err = os.Create(tasksFile)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(strings.Join(updatedTasks, "\n")); err != nil {
		return err
	}

	return nil
}

func DeleteAllAgentTasks(agentName string, isClient bool) error {
	tasksFile, err := GetAgentTasksFile(agentName, isClient)
	if err != nil {
		return err
	}

	if err := os.Truncate(tasksFile, 0); err != nil {
		return err
	}
	return nil
}

func WriteAgentLoot(
	agentName string,
	taskName string,
	taskResult string,
	isClient bool,
) (
	taskFile string,
	err error,
) {
	lootDir, err := GetAgentLootDir(agentName, isClient)
	if err != nil {
		return "", err
	}

	if taskName == "" {
		return "", fmt.Errorf("no task")
	}

	currDateTime := meta.GetCurrentDateTime()
	filename := meta.GetCurrentDateTimeNumbersOnly()

	lootFile := fmt.Sprintf("%s/%s", lootDir, "loot_"+filename+".txt")

	label := currDateTime + " : " + taskName
	labelUnderBar := strings.Repeat("=", len(label))

	err = os.WriteFile(
		lootFile,
		[]byte(
			label+"\n"+
				labelUnderBar+"\n"+
				taskResult+"\n",
		),
		0644,
	)
	if err != nil {
		return taskFile, err
	}

	return taskFile, nil
}

func WriteAgentLootFile(
	agentName string,
	data []byte,
	isClient bool,
	fileType string,
) (filename string, err error) {
	lootDir, err := GetAgentLootDir(agentName, isClient)
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(fileType, "procdump ") {
		targetDir := lootDir + "/procdumps"
		pid := strings.Split(fileType, " ")[1]
		filename = fmt.Sprintf("%s/procdump_%s_%s.dmp", targetDir, pid, meta.GetCurrentDateTimeNumbersOnly())
	} else if fileType == "screenshot" {
		targetDir := lootDir + "/screenshots"
		filename = fmt.Sprintf("%s/screenshot_%s.png", targetDir, meta.GetCurrentDateTimeNumbersOnly())
	}

	if filename == "" {
		return "", fmt.Errorf("filename is not specifed")
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return "", err
	}

	return filename, nil
}

func ReadAllAgentLoot(agentName string, isClient bool) ([]string, error) {
	lootDir, err := GetAgentLootDir(agentName, isClient)

	allContents := []string{}

	err = filepath.Walk(lootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.Contains(path, "loot_") {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			allContents = append(allContents, string(contents))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return allContents, nil
}

func DeleteAllAgentLoot(agentName string, isClient bool) error {
	lootDir, err := GetAgentLootDir(agentName, isClient)
	if err != nil {
		return err
	}

	filepath.Walk(lootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.Contains(path, "loot_") {
			err := os.Remove(path)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return nil
}
