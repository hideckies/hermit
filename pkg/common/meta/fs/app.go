package metafs

import (
	"fmt"
	"os"
)

func GetAppDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/.hermit", homeDir), nil
}

func MakeAppDirs(isClient bool) error {
	appDir, err := GetAppDir()
	if err != nil {
		return err
	}

	// ~/.hermit
	err = os.MkdirAll(appDir, PERM)
	if err != nil {
		return err
	}

	if isClient {
		clientDir := appDir + "/client"

		if err := os.MkdirAll(clientDir+"/agents", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(clientDir+"/certs", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(clientDir+"/configs", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(clientDir+"/listeners", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(clientDir+"/logs", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(clientDir+"/payloads", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(clientDir+"/tmp", PERM); err != nil {
			return err
		}
	} else {
		serverDir := appDir + "/server"

		if err := os.MkdirAll(serverDir+"/agents", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(serverDir+"/certs", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(serverDir+"/configs", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(serverDir+"/listeners", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(serverDir+"/logs", PERM); err != nil {
			return err
		}
		if err := os.MkdirAll(serverDir+"/tmp", PERM); err != nil {
			return err
		}
	}
	return nil
}
