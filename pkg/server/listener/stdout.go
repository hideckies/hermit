package listener

import (
	"fmt"
	"strings"

	"github.com/hideckies/hermit/pkg/common/stdout"
)

func PrintListeners(liss []*Listener) {
	if len(liss) == 0 {
		stdout.LogWarn("There are no listeners.")
		return
	}

	tHead := []string{"ID", "NAME", "URL", "DOMAINS", "ACTIVE"}
	tRows := [][]string{}
	for _, lis := range liss {
		active := "active"
		if !lis.Active {
			active = "inactive"
		}

		tRows = append(tRows, []string{
			fmt.Sprint(lis.Id),
			lis.Name,
			fmt.Sprintf("%s://%s:%d", strings.ToLower(lis.Protocol), lis.Addr, lis.Port),
			strings.Join(lis.Domains, ","),
			active,
		})
	}

	stdout.LogSuccess("")
	stdout.PrintTable(tHead, tRows)
	fmt.Println()
}
