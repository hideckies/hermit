package stdout

import (
	"fmt"
	"log"

	"github.com/fatih/color"
)

var processMark = fmt.Sprintf("[%s]", color.HiGreenString("*"))
var successMark = fmt.Sprintf("[%s]", color.HiCyanString("+"))
var warnMark = fmt.Sprintf("[%s]", color.HiYellowString("!"))
var failedMark = fmt.Sprintf("[%s]", color.HiRedString("x"))

func LogInfo(text string) {
	fmt.Printf("%s %s\n", processMark, text)
	log.Printf("[INFO] %s\n", text)
}

func LogSuccess(text string) {
	fmt.Printf("%s %s\n", successMark, text)
	log.Printf("[SUCCESS] %s\n", text)
}

func LogWarn(text string) {
	fmt.Printf("%s %s\n", warnMark, text)
	log.Printf("[WARN] %s\n", text)
}

func LogFailed(text string) {
	fmt.Printf("%s %s\n", failedMark, text)
	log.Printf("[ERROR] %s\n", text)
}
