package metafs

import (
	"fmt"
	"os"
	"path/filepath"
)

func GetListenersDir(isClient bool) (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	if isClient {
		return fmt.Sprintf("%s/client/listeners", appDir), nil
	} else {
		return fmt.Sprintf("%s/server/listeners", appDir), nil
	}
}

func GetListenerDir(listenerName string, isClient bool) (string, error) {
	listenersDir, err := GetListenersDir(isClient)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", listenersDir, listenerName), nil
}

func GetListenerPayloadsDir(listenerName string, isClient bool) (string, error) {
	listenerDir, err := GetListenerDir(listenerName, isClient)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/payloads", listenerDir), nil
}

func GetListenerPayloadPaths(listenerName string, isClient bool, fileNamesOnly bool) ([]string, error) {
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

func MakeListenerChildDirs(listenerName string, isClient bool) error {
	listenerDir, err := GetListenerDir(listenerName, isClient)
	if err != nil {
		return err
	}

	// Check if the folder already exists
	if _, err := os.Stat(listenerDir); err == nil {
		// Already exists
		return nil
	}

	// Make directories
	if err := os.MkdirAll(listenerDir+"/certs", PERM); err != nil {
		return err
	}
	if err := os.MkdirAll(listenerDir+"/payloads", PERM); err != nil {
		return err
	}

	return nil
}
