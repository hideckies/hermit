package task

import (
	"fmt"
	"strings"
)

func SetTaskWithSrcDest(task string) (string, error) {
	taskSplit := strings.Split(task, " ")
	if len(taskSplit) != 3 {
		return "", fmt.Errorf("invalid number of arguments")
	}

	cmd := taskSplit[0]
	src := taskSplit[1]
	dest := taskSplit[2]

	if dest == "." {
		srcSplit := strings.Split(src, "/")
		dest = srcSplit[len(srcSplit)-1]
	}
	if dest[len(dest)-1] == '/' {
		dest = fmt.Sprintf("%s%s", dest, src)
	}
	task = cmd + " " + src + " " + dest

	return task, nil
}
