package metafs

import (
	"fmt"
	"log"
	"os"

	"github.com/hideckies/hermit/pkg/common/meta"
)

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

func OpenLogFile(isClient bool) (*os.File, error) {
	logsDir, err := GetLogsDir(isClient)
	if err != nil {
		return nil, err
	}
	logFilePath := fmt.Sprintf("%s/%s.log", logsDir, meta.GetCurrentDate())
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	log.SetOutput(logFile)

	return logFile, nil
}
