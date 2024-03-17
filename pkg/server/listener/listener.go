package listener

import (
	"fmt"
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

func (lis *Listener) GetURL() string {
	return fmt.Sprintf(fmt.Sprintf("%s://%s:%d", strings.ToLower(lis.Protocol), lis.Addr, lis.Port))
}

// This includes domain associated URLs such as "https://evil.com:12345"
func (lis *Listener) GetAllURLs() []string {
	urls := []string{}
	urls = append(urls, lis.GetURL())

	if len(lis.Domains) > 0 {
		for _, domain := range lis.Domains {
			if domain == "" {
				continue
			}
			domainURL := fmt.Sprintf("%s://%s:%d", strings.ToLower(lis.Protocol), domain, lis.Port)
			urls = append(urls, domainURL)
		}
	}

	return urls
}

func (lis *Listener) GetActiveString() string {
	if lis.Active {
		return "active"
	} else {
		return "inactive"
	}
}
