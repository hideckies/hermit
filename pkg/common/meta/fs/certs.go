package metafs

import "fmt"

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
