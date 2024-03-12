package wizard

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hideckies/hermit/pkg/common/stdin"
	"github.com/hideckies/hermit/pkg/common/stdout"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/hideckies/hermit/pkg/server/listener"
)

func WizardListenerStart(host string, domains []string) (*listener.Listener, error) {
	stdout.PrintBannerListener()
	stdout.LogInfo("Set listener options.")

	var oProtocol string
	for {
		res, err := stdin.Select("Protocol", []string{"HTTPS"})
		if err != nil {
			stdout.LogFailed("Invalid input.")
			continue
		}
		oProtocol = strings.ToLower(res)
		break
	}

	var oAddr string = host
	for {
		res, err := stdin.ReadInput("Bind Address", oAddr)
		if err != nil {
			stdout.LogFailed("Invalid input.")
			continue
		}
		oAddr = res
		break
	}

	var oPort uint16 = utils.GenerateRandomPort()
	for {
		res, err := stdin.ReadInput("Bind Port", fmt.Sprintf("%d", oPort))
		if err != nil {
			stdout.LogFailed("Invalid input.")
			continue
		}

		resU64, err := strconv.ParseUint(res, 10, 64)
		if err != nil {
			stdout.LogFailed("Invalid port number.")
			continue
		}
		oPort = uint16(resU64)
		break
	}

	var oDomains []string = domains
	for {
		res, err := stdin.ReadInput("Domains (separate with ',')", strings.Join(oDomains, ","))
		if err != nil {
			stdout.LogFailed("Invalid input.")
			continue
		}
		oDomains = strings.Split(res, ",")
		break
	}

	table := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("URL", fmt.Sprintf("%s://%s:%d", strings.ToLower(oProtocol), oAddr, oPort)),
		stdout.NewSingleTableItem("Domains", strings.Join(oDomains, ",")),
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
	if !proceed {
		return nil, fmt.Errorf("canceled")
	}

	return listener.NewListener(0, "", "", oProtocol, oAddr, oPort, oDomains, false), nil
}
