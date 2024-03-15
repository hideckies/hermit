package metafs

import "fmt"

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
