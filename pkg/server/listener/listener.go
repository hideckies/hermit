package listener

import (
	"strings"

	"github.com/google/uuid"
	"github.com/hideckies/hermit/pkg/common/utils"
)

type Listener struct {
	Id       uint
	Uuid     string
	Name     string
	Protocol string
	Addr     string
	Port     uint16
	Domains  []string
	Active   bool
}

func NewListener(
	id uint,
	_uuid string,
	name string,
	protocol string,
	addr string,
	port uint16,
	domains []string,
	active bool,
) *Listener {
	listenerUuid := _uuid
	if _uuid == "" {
		listenerUuid = uuid.NewString()
	}
	listenerName := name
	if name == "" {
		listenerName = utils.GenerateRandomAnimalName(false, strings.ToLower(protocol))
	}
	return &Listener{
		Id:       id,
		Uuid:     listenerUuid,
		Name:     listenerName,
		Protocol: protocol,
		Addr:     addr,
		Port:     port,
		Domains:  domains,
		Active:   active,
	}
}
