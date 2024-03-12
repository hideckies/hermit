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

	tHead := []string{"ID", "NAME", "IP", "OS/ARCH", "HOSTNAME", "LISTENER", "SLEEP", "JITTER", "KILLDATE"}
	tRows := [][]string{}
	for _, ag := range ags {
		killDate := meta.GetDateTimeFromTimestamp(int(ag.KillDate))

		tRows = append(tRows, []string{
			fmt.Sprint(ag.Id),
			ag.Name,
			ag.Ip,
			fmt.Sprintf("%s/%s", ag.OS, ag.Arch),
			ag.Hostname,
			ag.ListenerName,
			fmt.Sprint(ag.Sleep),
			fmt.Sprint(ag.Jitter),
			killDate,
		})
	}

	stdout.LogSuccess("")
	stdout.PrintTable(tHead, tRows)
	fmt.Println()
}
