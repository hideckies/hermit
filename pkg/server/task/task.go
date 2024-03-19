package task

import (
	"fmt"
	"strings"

	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdin"
)

func SetTask(task string, agentName string) error {
	// Adjust arguments
	switch {
	case strings.HasPrefix(task, "cp "),
		strings.HasPrefix(task, "download "),
		strings.HasPrefix(task, "mv "),
		strings.HasPrefix(task, "upload "):

		taskSplit := strings.Split(task, " ")
		if len(taskSplit) != 3 {
			return fmt.Errorf("invalid number of arguments")
		}

		cmd := taskSplit[0]
		src := taskSplit[1]
		dest := taskSplit[2]

		if dest == "." {
			srcSplit := strings.Split(src, "/")
			dest = srcSplit[len(srcSplit)-1]
		}
		if dest[len(dest)-1] == '/' {
			dest = fmt.Sprintf("%s%s", dest, src)
		}
		task = cmd + " " + src + " " + dest

	case task == "ls":
		task = "ls ."

	case task == "reg subkeys", task == "reg values":

		var label string
		var items []string
		if task == "reg subkeys" {
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
		} else if task == "reg values" {
			label = "Specify keyname to read value"
			items = []string{
				"HKCU\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
				"HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
				"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
				"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
				"HKLM\\Software\\Policies\\Microsoft Services\\AdmPwd",
				"HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
				"Custom...",
			}
		}
		res, err := stdin.Select(label, items)
		if err != nil {
			return err
		}

		if res == "Custom..." {
			res, err = stdin.ReadInput("Enter keyname", "")
			if err != nil {
				return err
			}
			if res == "" {
				return fmt.Errorf("empty value not allowed")
			}
		}

		// Parse selected value
		resSplit := strings.Split(res, "\\")
		rootKey := resSplit[0]
		subKey := strings.Join(resSplit[1:], "\\")

		// Recurse
		isRecurse := false
		for {
			yes, err := stdin.Confirm("Recurse?")
			if err != nil {
				continue
			}
			isRecurse = yes
			break
		}
		task = task + " " + fmt.Sprintf("%t", isRecurse) + " " + rootKey + " " + subKey

	}

	err := metafs.WriteAgentTask(agentName, task, false)
	if err != nil {
		return err
	}
	return nil
}
