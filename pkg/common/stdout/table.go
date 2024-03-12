package stdout

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/hideckies/hermit/pkg/common/utils"
	"github.com/rodaine/table"
)

type SingleTableItem struct {
	Key   string
	Value string
}

func NewSingleTableItem(key string, value string) SingleTableItem {
	return SingleTableItem{
		Key:   key,
		Value: value,
	}
}

func PrintSingleTable(title string, table []SingleTableItem) {
	fmt.Printf("\n%s:\n\n", title)

	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent)
	for _, item := range table {
		fmt.Fprintf(
			writer,
			"%s %s\t: %s\n",
			color.HiGreenString("*"),
			color.HiGreenString(item.Key),
			color.HiCyanString(item.Value),
		)
	}
	fmt.Fprintln(writer)
	writer.Flush()
}

func PrintTable(headers []string, rows [][]string) {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	headersIface := utils.ConvertStringsToInterfaces(headers)

	tbl := table.New(headersIface...)
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, row := range rows {
		rowIface := utils.ConvertStringsToInterfaces(row)
		tbl.AddRow(rowIface...)
	}

	tbl.Print()
}
