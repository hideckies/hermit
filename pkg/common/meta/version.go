package meta

import "fmt"

const VERSION = "v0.0.0"

func GetVersion() string {
	return fmt.Sprintf("Hermit %s", VERSION)
}

func PrintVersion() {
	fmt.Println(GetVersion())
}
