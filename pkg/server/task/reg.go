package task

import (
	"fmt"
	"strings"

	"github.com/hideckies/hermit/pkg/common/stdin"
)

func readCustomRegKey() (string, error) {
	res, err := stdin.ReadInput("Enter keyname", "")
	if err != nil {
		return "", err
	}
	if res == "" {
		return "", fmt.Errorf("empty value not allowed")
	}

	return res, nil
}

func parseRegKey(keyname string) (rootKey string, subKey string) {
	keySplit := strings.Split(keyname, "\\")
	rootKey = keySplit[0]
	subKey = strings.Join(keySplit[1:], "\\")
	return rootKey, subKey
}

func isRecurse() bool {
	isRecurse := false
	for {
		yes, err := stdin.Confirm("Recurse?")
		if err != nil {
			continue
		}
		isRecurse = yes
		break
	}
	return isRecurse
}

func SetTaskReg(task string) (string, error) {
	var err error
	var label string
	var items []string

	var keyname string
	var rootKey string
	var subKey string

	if task == "reg add" {
		label = "Specify keyname to add"
		items = []string{
			"HKLM\\Software\\EvilHermit",
			"Custom...",
		}
		keyname, err = stdin.Select(label, items)
		if err != nil {
			return "", err
		}
		if keyname == "Custom..." {
			keyname, err = readCustomRegKey()
			if err != nil {
				return "", err
			}
		}
		rootKey, subKey = parseRegKey(keyname)
		task = task + " " + rootKey + " " + subKey
	} else if task == "reg delete" {
		label = "Specify keyname to delete"
		items = []string{
			"Custom...",
		}
		keyname, err = stdin.Select(label, items)
		if err != nil {
			return "", err
		}
		if keyname == "Custom..." {
			keyname, err = readCustomRegKey()
			if err != nil {
				return "", err
			}
		}
		rootKey, subKey = parseRegKey(keyname)
		task = task + " " + rootKey + " " + subKey
	} else if task == "reg subkeys" {
		label = "Specify keyname to enumerate"
		items = []string{
			"HKCU\\AppEvents",
			"HKCU\\Control Panel",
			"HKCU\\Environment",
			"HKCU\\Software",
			"HKLM\\SAM",
			"HKLM\\Security",
			"HKLM\\Software",
			"HKLM\\Hardware",
			"Custom...",
		}
		keyname, err = stdin.Select(label, items)
		if err != nil {
			return "", err
		}
		if keyname == "Custom..." {
			keyname, err = readCustomRegKey()
			if err != nil {
				return "", err
			}
		}
		rootKey, subKey = parseRegKey(keyname)
		isRecurse := isRecurse()
		task = task + " " + fmt.Sprintf("%t", isRecurse) + " " + rootKey + " " + subKey
	} else if task == "reg values" {
		label = "Specify keyname to read value"
		items = []string{
			"HKCU\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
			"HKLM\\Security\\Policy\\Secrets",
			"HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
			"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
			"HKLM\\Software\\Policies\\Microsoft Services\\AdmPwd",
			"HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
			"Custom...",
		}
		keyname, err = stdin.Select(label, items)
		if err != nil {
			return "", err
		}
		if keyname == "Custom..." {
			keyname, err = readCustomRegKey()
			if err != nil {
				return "", err
			}
		}
		rootKey, subKey = parseRegKey(keyname)
		isRecurse := isRecurse()
		task = task + " " + fmt.Sprintf("%t", isRecurse) + " " + rootKey + " " + subKey
	} else if task == "reg write" {
		label = "Specify keyname to write"
		items = []string{
			"Custom...",
		}
		keyname, err = stdin.Select(label, items)
		if err != nil {
			return "", err
		}
		if keyname == "Custom..." {
			keyname, err = readCustomRegKey()
			if err != nil {
				return "", err
			}
		}
		rootKey, subKey = parseRegKey(keyname)
		task = task + " " + rootKey + " " + subKey
	}

	return task, nil
}
