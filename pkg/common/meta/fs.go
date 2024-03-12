package meta

import (
	"bufio"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func GetAppDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/.hermit", homeDir), nil
}

func MakeAppDirs(isClient bool) error {
	var perm fs.FileMode = 0765

	appDir, err := GetAppDir()
	if err != nil {
		return err
	}

	// ~/.hermit
	err = os.MkdirAll(appDir, perm)
	if err != nil {
		return err
	}

	if isClient {
		clientCertsDir := fmt.Sprintf("%s/client/certs", appDir)
		if err := os.MkdirAll(clientCertsDir, perm); err != nil {
			return err
		}
		clientConfigsDir := fmt.Sprintf("%s/client/configs", appDir)
		if err := os.MkdirAll(clientConfigsDir, perm); err != nil {
			return err
		}
		clientLogsDir := fmt.Sprintf("%s/client/logs", appDir)
		if err := os.MkdirAll(clientLogsDir, perm); err != nil {
			return err
		}
		clientLootDir := fmt.Sprintf("%s/client/loot", appDir)
		if err := os.MkdirAll(clientLootDir, perm); err != nil {
			return err
		}
		clientTmpDir := fmt.Sprintf("%s/client/tmp", appDir)
		if err := os.MkdirAll(clientTmpDir, perm); err != nil {
			return err
		}
	} else {
		serverCertsDir := fmt.Sprintf("%s/server/certs", appDir)
		if err := os.MkdirAll(serverCertsDir, perm); err != nil {
			return err
		}
		serverConfigsDir := fmt.Sprintf("%s/server/configs", appDir)
		if err := os.MkdirAll(serverConfigsDir, perm); err != nil {
			return err
		}
		serverLogsDir := fmt.Sprintf("%s/server/logs", appDir)
		if err := os.MkdirAll(serverLogsDir, perm); err != nil {
			return err
		}
		serverLootDir := fmt.Sprintf("%s/server/loot", appDir)
		if err := os.MkdirAll(serverLootDir, perm); err != nil {
			return err
		}
		serverTmpDir := fmt.Sprintf("%s/server/tmp", appDir)
		if err := os.MkdirAll(serverTmpDir, perm); err != nil {
			return err
		}
	}
	return nil
}

func MakeListenerDir(listenerName string, isClient bool) error {
	var perm fs.FileMode = 0765

	appDir, err := GetAppDir()
	if err != nil {
		return err
	}

	var listenerDir string
	if isClient {
		listenerDir = fmt.Sprintf("%s/client/listeners/%s", appDir, listenerName)
	} else {
		listenerDir = fmt.Sprintf("%s/server/listeners/%s", appDir, listenerName)
	}

	// Check if the folder already exists
	if _, err := os.Stat(listenerDir); err == nil {
		// Already exists
		return nil
	}

	// Make directories
	if err := os.MkdirAll(listenerDir, perm); err != nil {
		return err
	}
	certsDir := fmt.Sprintf("%s/certs", listenerDir)
	if err := os.MkdirAll(certsDir, perm); err != nil {
		return err
	}
	payloadsDir := fmt.Sprintf("%s/payloads", listenerDir)
	if err := os.MkdirAll(payloadsDir, perm); err != nil {
		return err
	}

	return nil
}

func GetListenerDir(listenerName string, isClient bool) (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	var listenerDir string
	if isClient {
		listenerDir = fmt.Sprintf("%s/client/listeners/%s", appDir, listenerName)
	} else {
		listenerDir = fmt.Sprintf("%s/server/listeners/%s", appDir, listenerName)
	}
	return listenerDir, nil
}

func GetPayloadsDir(listenerName string, isClient bool) (string, error) {
	listenerDir, err := GetListenerDir(listenerName, isClient)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/payloads", listenerDir), nil
}

func GetPayloadPaths(listenerName string, isClient bool, fileNamesOnly bool) ([]string, error) {
	listenerDir, err := GetListenerDir(listenerName, isClient)
	if err != nil {
		return nil, err
	}
	payloadsDir := fmt.Sprintf("%s/payloads", listenerDir)

	payloads := []string{}
	filepath.Walk(payloadsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		if fileNamesOnly {
			payloads = append(payloads, filepath.Base(path))
		} else {
			payloads = append(payloads, path)
		}
		return nil
	})

	return payloads, nil
}

func GetCertsDir(listenerDir string) (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	var certsDir string
	if listenerDir == "" {
		// Get root certs directory
		certsDir = fmt.Sprintf("%s/server/certs", appDir)
	} else {
		certsDir = fmt.Sprintf("%s/server/listeners/%s/certs", appDir, listenerDir)
	}
	return certsDir, nil
}

func GetConfigsDir(isClient bool) (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	if isClient {
		return fmt.Sprintf("%s/client/configs", appDir), nil
	} else {
		return fmt.Sprintf("%s/server/configs", appDir), nil
	}
}

func GetLogsDir(isClient bool) (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	if isClient {
		return fmt.Sprintf("%s/client/logs", appDir), nil
	} else {
		return fmt.Sprintf("%s/server/logs", appDir), nil
	}
}

func GetLootDir(isClient bool) (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	if isClient {
		return fmt.Sprintf("%s/client/loot", appDir), nil
	} else {
		return fmt.Sprintf("%s/server/loot", appDir), nil
	}
}

func GetLootAgentDir(agentName string, isClient bool) (string, error) {
	lootDir, err := GetLootDir(false)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", lootDir, agentName), nil
}

func GetTasksFile(agentName string, isClient bool) (string, error) {
	agentDir, err := GetLootAgentDir(agentName, isClient)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%s/.tasks", agentDir), nil
}

func GetTempDir(isClient bool) (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	if isClient {
		return fmt.Sprintf("%s/client/tmp", appDir), nil
	} else {
		return fmt.Sprintf("%s/server/tmp", appDir), nil
	}
}

func GetDBPath() (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/server/hermit.db", appDir), nil
}

func OpenLogFile(isClient bool) (*os.File, error) {
	logsDir, err := GetLogsDir(isClient)
	if err != nil {
		return nil, err
	}
	logFilePath := fmt.Sprintf("%s/%s.log", logsDir, GetCurrentDate())
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	log.SetOutput(logFile)

	return logFile, nil
}

func MakeLootAgentDir(agentName string, isClient bool) error {
	lootDir, err := GetLootDir(isClient)
	if err != nil {
		return err
	}

	agentDir := fmt.Sprintf("%s/%s", lootDir, agentName)
	screenshotsDir := fmt.Sprintf("%s/screenshots", agentDir)
	err = os.MkdirAll(screenshotsDir, 0765)
	if err != nil {
		return err
	}
	return nil
}

func MakeTasksFile(agentName string, isClient bool) (tasksFile string, err error) {
	tasksFile, err = GetTasksFile(agentName, isClient)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(tasksFile); err != nil {
		newFile, err := os.Create(tasksFile)
		if err != nil {
			return tasksFile, err
		}
		newFile.Close()
	}

	return tasksFile, nil
}

func WriteTask(
	agentName string,
	taskName string,
	isClient bool,
) error {
	tasksFile, err := MakeTasksFile(agentName, isClient)
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

func ReadTasks(agentName string, isClient bool) ([]string, error) {
	tasksFile, err := GetTasksFile(agentName, isClient)
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

func DeleteTask(agentName string, taskName string, isClient bool) error {
	tasksFile, err := GetTasksFile(agentName, isClient)
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

func DeleteAllTasks(agentName string, isClient bool) error {
	agentDir, err := GetLootAgentDir(agentName, isClient)
	if err != nil {
		return err
	}

	tasksFile := fmt.Sprintf("%s/.tasks", agentDir)
	if err := os.Truncate(tasksFile, 0); err != nil {
		return err
	}
	return nil
}

func WriteTaskResultString(
	agentName string,
	taskName string,
	taskResult string,
	isClient bool,
) (
	taskFile string,
	err error,
) {
	agentDir, err := GetLootAgentDir(agentName, isClient)
	if err != nil {
		return "", err
	}

	if taskName == "" {
		return "", fmt.Errorf("no task")
	}

	currDateTime := GetCurrentDateTime()
	filename := GetCurrentDateTimeNumbersOnly()

	taskResultFile := fmt.Sprintf("%s/%s", agentDir, "result_"+filename+".txt")
	err = os.WriteFile(
		taskResultFile,
		[]byte(
			"Date:\n"+currDateTime+"\n\n"+"Task:\n"+taskName+"\n\n"+"Result:\n"+taskResult,
		),
		0644,
	)
	if err != nil {
		return taskFile, err
	}

	return taskFile, nil
}

func WriteScreenshot(
	agentName string,
	data []byte,
	isClient bool,
) (filename string, err error) {
	agentDir, err := GetLootAgentDir(agentName, isClient)
	if err != nil {
		return "", err
	}

	screenshotsDir := fmt.Sprintf("%s/screenshots", agentDir)
	filename = fmt.Sprintf("%s/screenshot_%s.png", screenshotsDir, GetCurrentDateTimeNumbersOnly())
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return "", err
	}

	return filename, nil
}

func ReadAllTaskResults(agentName string, isClient bool) ([]string, error) {
	agentDir, err := GetLootAgentDir(agentName, isClient)
	if err != nil {
		return nil, err
	}

	allContents := []string{}

	err = filepath.Walk(agentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, "/.tasks") {
			return nil
		}
		if strings.Contains(path, "/screenshots/") {
			return nil
		}

		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		allContents = append(allContents, string(contents))
		return nil
	})
	if err != nil {
		return nil, err
	}

	return allContents, nil
}

func DeleteAllTaskResults(agentName string, isClient bool) error {
	agentDir, err := GetLootAgentDir(agentName, isClient)
	if err != nil {
		return err
	}

	filepath.Walk(agentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, "/.tasks") {
			return nil
		}

		if !info.IsDir() {
			err := os.Remove(path)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return nil
}
