package agent

import "github.com/hideckies/hermit/pkg/common/utils"

type Agent struct {
	Id          uint
	Uuid        string
	Name        string
	Ip          string
	OS          string
	Arch        string
	Hostname    string
	ListenerURL string
	ImplantType string
	CheckInDate string
	Sleep       uint
	Jitter      uint
	KillDate    uint
}

func NewAgent(
	id uint,
	uuid string,
	name string,
	ip string,
	os string,
	arch string,
	hostname string,
	listenerURL string,
	implantType string,
	checkInDate string,
	sleep uint,
	jitter uint,
	killDate uint,
) *Agent {
	if name == "" {
		name = utils.GenerateRandomHumanName(false, "agent")
	}
	return &Agent{
		Id:          id,
		Uuid:        uuid,
		Name:        name,
		Ip:          ip,
		OS:          os,
		Arch:        arch,
		Hostname:    hostname,
		ListenerURL: listenerURL,
		ImplantType: implantType,
		CheckInDate: checkInDate,
		Sleep:       sleep,
		Jitter:      jitter,
		KillDate:    killDate,
	}
}
