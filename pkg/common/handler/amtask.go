package handler

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/client/rpc"
	cliState "github.com/hideckies/hermit/pkg/client/state"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	servState "github.com/hideckies/hermit/pkg/server/state"
	_task "github.com/hideckies/hermit/pkg/server/task"
)

func HandleAmTaskSet(
	task *_task.Task,
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	// Encode task to JSON string.
	taskJSON, err := task.Encode()
	if err != nil {
		return err
	}

	if serverState != nil {
		// Add the task to the '.tasks' file
		err = metafs.WriteAgentTask(serverState.AgentMode.Name, taskJSON, false)
		if err != nil {
			return err
		}
	} else if clientState != nil {
		// Send request to the server for setting a task
		err = rpc.RequestTaskSetByAgentName(clientState, taskJSON)
		if err != nil {
			return err
		}
	}

	stdout.LogSuccess("Task set successfully.")
	return nil
}

func HandleAmTaskClear(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		res, err := stdin.Confirm("Are you sure you want to delete all tasks?")
		if err != nil {
			return err
		}
		if !res {
			return fmt.Errorf("canceled")
		}

		err = metafs.DeleteAllAgentTasks(serverState.AgentMode.Name, false)
		if err != nil {
			return err
		}

		stdout.LogSuccess("All tasks deleted successfully.")
	} else if clientState.Conf != nil {
		res, err := stdin.Confirm("Are you sure you want to delete all tasks?")
		if err != nil {
			return err
		}
		if !res {
			return fmt.Errorf("canceled")
		}

		err = rpc.RequestTaskClearByAgentName(clientState)
		if err != nil {
			return err
		}

		stdout.LogSuccess("All tasks deleted successfully.")
	}

	return nil
}

func HandleAmTaskList(
	serverState *servState.ServerState,
	clientState *cliState.ClientState,
) error {
	if serverState.Conf != nil {
		tasks, err := metafs.ReadAgentTasks(serverState.AgentMode.Name, false)
		if err != nil {
			return err
		}
		if len(tasks) == 0 {
			return fmt.Errorf("task not set")
		}

		stdout.LogSuccess("Task List")
		for _, task := range tasks {
			fmt.Println(task)
		}
	} else if clientState.Conf != nil {
		taskList, err := rpc.RequestTaskListByAgentName(clientState)
		if err != nil {
			return err
		}

		stdout.LogSuccess("")
		fmt.Println(taskList)
	}

	return nil
}
