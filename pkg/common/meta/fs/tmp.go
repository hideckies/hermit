package metafs

import "fmt"

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
