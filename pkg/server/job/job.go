package job

import (
	"fmt"
	"os"
)

type ListenerJob struct {
	ListenerUUID string
	ChReady      chan string
	ChError      chan string
	ChQuit       chan string
	ChReqQuit    chan string
}

type Job struct {
	ChServerStarted chan bool
	ChQuit          chan os.Signal
	ListenerJobs    []*ListenerJob
}

func NewJob() *Job {
	return &Job{
		ChServerStarted: make(chan bool),
		ChQuit:          make(chan os.Signal, 4),
		ListenerJobs:    []*ListenerJob{},
	}
}

func (j *Job) NewListenerJob(listenerUUID string) *ListenerJob {
	newListenerJob := &ListenerJob{
		ListenerUUID: listenerUUID,
		ChReady:      make(chan string),
		ChError:      make(chan string),
		ChQuit:       make(chan string),
		ChReqQuit:    make(chan string),
	}

	j.ListenerJobs = append(j.ListenerJobs, newListenerJob)

	return newListenerJob
}

func (j *Job) GetListenerJob(listenerUUID string) (*ListenerJob, error) {
	for _, lisJob := range j.ListenerJobs {
		if lisJob.ListenerUUID == listenerUUID {
			return lisJob, nil
		}
	}

	return nil, fmt.Errorf("listener job not found")
}

func (j *Job) RemoveListenerJob(listenerUUID string) error {
	var targetIndex int = -1

	for idx, lisJob := range j.ListenerJobs {
		if lisJob.ListenerUUID == listenerUUID {
			targetIndex = idx
			break
		}
	}

	if targetIndex == -1 {
		return fmt.Errorf("listener job not found")
	}

	// Remove the listener job
	j.ListenerJobs = append(j.ListenerJobs[:targetIndex], j.ListenerJobs[targetIndex+1:]...)

	return nil
}
