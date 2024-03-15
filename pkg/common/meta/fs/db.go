package metafs

import "fmt"

func GetDBPath() (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/server/hermit.db", appDir), nil
}
