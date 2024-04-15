package agent

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/common/meta"
	"github.com/hideckies/hermit/pkg/common/stdout"
)

func PrintAgents(ags []*Agent) {
	if len(ags) == 0 {
		stdout.LogWarn("There are no agents.")
		return
	}

	tHead := []string{
		"ID",
		"Name",
		"IP",
		"OS/Arch",
		"Hostname",
		"ListenerURL",
		"ImplantType",
		"CheckIn",
	}
	tRows := [][]string{}
	for _, ag := range ags {
		tRows = append(tRows, []string{
			fmt.Sprint(ag.Id),
			ag.Name,
			ag.Ip,
			fmt.Sprintf("%s/%s", ag.OS, ag.Arch),
			ag.Hostname,
			ag.ListenerURL,
			ag.ImplantType,
			ag.CheckInDate,
		})
	}

	stdout.LogSuccess("")
	stdout.PrintTable(tHead, tRows)
	fmt.Println()
}

func PrintAgentDetails(ag *Agent) {
	items := []stdout.SingleTableItem{
		stdout.NewSingleTableItem("ID", fmt.Sprint(ag.Id)),
		stdout.NewSingleTableItem("Name", ag.Name),
		stdout.NewSingleTableItem("UUID", ag.Uuid),
		stdout.NewSingleTableItem("IP", ag.Ip),
		stdout.NewSingleTableItem("OS/Arch", fmt.Sprintf("%s/%s", ag.OS, ag.Arch)),
		stdout.NewSingleTableItem("Hostname", ag.Hostname),
		stdout.NewSingleTableItem("Listener URL", ag.ListenerURL),
		stdout.NewSingleTableItem("Implant Type", ag.ImplantType),
		stdout.NewSingleTableItem("Check In", ag.CheckInDate),
		stdout.NewSingleTableItem("Sleep", fmt.Sprint(ag.Sleep)),
		stdout.NewSingleTableItem("Jitter", fmt.Sprint(ag.Jitter)),
		stdout.NewSingleTableItem("KillDate", meta.GetDateTimeFromTimestamp(int(ag.KillDate))),
		stdout.NewSingleTableItem("AES Key", ag.AES.Key.Base64),
		stdout.NewSingleTableItem("AES IV", ag.AES.IV.Base64),
	}

	stdout.LogSuccess("")
	stdout.PrintSingleTable("AGENT", items)
}
