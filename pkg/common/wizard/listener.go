package wizard

import (
	"strings"

	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
)

func ConfirmListenerNew(url string, domains []string) bool {

	table := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("URL", url),
		stdout.NewSingleTableItem("Domains", strings.Join(domains, ",")),
	}
	stdout.PrintSingleTable("Listener Options", table)

	var proceed bool
	for {
		res, err := stdin.Confirm("Proceed?")
		if err != nil {
			continue
		}
		proceed = res
		break
	}
	return proceed
}
