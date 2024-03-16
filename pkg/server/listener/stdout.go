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

	tHead := []string{"ID", "Name", "URL", "Domains", "Active"}
	tRows := [][]string{}
	for _, lis := range liss {
		active := "active"
		if !lis.Active {
			active = "inactive"
		}

		tRows = append(tRows, []string{
			fmt.Sprint(lis.Id),
			lis.Name,
			lis.GetURL(),
			strings.Join(lis.Domains, ","),
			active,
		})
	}

	stdout.LogSuccess("")
	stdout.PrintTable(tHead, tRows)
	fmt.Println()
}

func PrintListenerDetails(lis *Listener) {
	items := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("ID", fmt.Sprint(lis.Id)),
		stdout.NewSingleTableItem("Name", lis.Name),
		stdout.NewSingleTableItem("UUID", lis.Uuid),
		stdout.NewSingleTableItem("URL", lis.GetURL()),
		stdout.NewSingleTableItem("Domains", strings.Join(lis.Domains, ",")),
		stdout.NewSingleTableItem("Active", lis.GetActiveString()),
	}

	stdout.LogSuccess("")
	stdout.PrintSingleTable("LISTENER", items)
}
