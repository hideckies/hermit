package agent

import "github.com/hideckies/hermit/pkg/common/utils"

type Agent struct {
	Id           uint
	Uuid         string
	Name         string
	Ip           string
	OS           string
	Arch         string
	Hostname     string
	ListenerName string
	Sleep        uint
	Jitter       uint
	KillDate     uint
}

func NewAgent(
	id uint,
	uuid string,
	name string,
	ip string,
	os string,
	arch string,
	hostname string,
	listenerName string,
	sleep uint,
	jitter uint,
	killDate uint,
) *Agent {
	if name == "" {
		name = utils.GenerateRandomHumanName(false, "agent")
	}
	return &Agent{
		Id:           id,
		Uuid:         uuid,
		Name:         name,
		Ip:           ip,
		OS:           os,
		Arch:         arch,
		Hostname:     hostname,
		ListenerName: listenerName,
		Sleep:        sleep,
		Jitter:       jitter,
		KillDate:     killDate,
	}
}
