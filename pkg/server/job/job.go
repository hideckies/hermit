package job

import "os"

type Job struct {
	ChServerStarted   chan bool
	ChQuit            chan os.Signal
	ChListenerReady   chan string
	ChListenerError   chan string
	ChListenerQuit    chan string
	ChReqListenerQuit chan string
}

func NewJob() *Job {
	return &Job{
		ChServerStarted:   make(chan bool),
		ChQuit:            make(chan os.Signal, 4),
		ChListenerReady:   make(chan string),
		ChListenerError:   make(chan string),
		ChListenerQuit:    make(chan string),
		ChReqListenerQuit: make(chan string),
	}
}
