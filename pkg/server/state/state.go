package state

import (
	"os"
	"runtime"

	"github.com/alecthomas/kong"
	"github.com/hideckies/hermit/pkg/common/config"
	"github.com/hideckies/hermit/pkg/server/db"
	"github.com/hideckies/hermit/pkg/server/job"
	"github.com/hideckies/hermit/pkg/server/operator"
)

type AgentMode struct {
	UUID string // agent UUID
	Name string // agent name
	CWD  string // current working directory of agent
}

type ServerState struct {
	Conf      *config.ServerConfig
	CWD       string // Current working directory
	NumCPU    int    // Number of CPU usable at runtime
	DB        *db.Database
	Job       *job.Job
	Parser    *kong.Kong
	Operator  *operator.Operator // Current operator
	AgentMode *AgentMode
	Continue  bool // Is console continue or not
}

func NewServerState(conf *config.ServerConfig, db *db.Database, job *job.Job) (*ServerState, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	return &ServerState{
		Conf:      conf,
		CWD:       cwd,
		NumCPU:    runtime.NumCPU(),
		DB:        db,
		Job:       job,
		AgentMode: &AgentMode{},
		Continue:  true,
	}, nil
}
