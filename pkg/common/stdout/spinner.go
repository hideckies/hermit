package stdout

import (
	"fmt"
	"time"

	"github.com/briandowns/spinner"
)

func NewSpinner(text string) *spinner.Spinner {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Suffix = fmt.Sprintf(" %s", text)
	s.Color("green", "bold")

	return s
}
