package meta

import (
	"fmt"
	"os"
	"os/user"
	"regexp"
	"strings"
	"time"
)

func GetCurrentUser() string {
	user, err := user.Current()
	if err != nil {
		return "anonymous"
	}

	return user.Username
}

func GetCurrentDir() string {
	currentDir, err := os.Getwd()
	if err != nil {
		return "x"
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return currentDir
	}

	// Replace the home path
	currentDir = strings.Replace(currentDir, homeDir, "~", 1)

	return currentDir
}

func GetCurrentDate() string {
	now := time.Now().UTC()
	return now.Format("2006-01-02")
}

func GetCurrentDateTime() string {
	now := time.Now().UTC()
	return now.Format("2006-01-02 15:04:05")
}

func GetCurrentDateTimeNumbersOnly() string {
	currDateTime := GetCurrentDateTime()
	s := strings.ReplaceAll(currDateTime, "-", "")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func GetCurrentTimestamp() int {
	now := time.Now().UTC()
	return int(now.Unix())
}

func GetFutureDate(years int, months int, days int) string {
	now := time.Now().UTC()
	future := now.AddDate(years, months, days)
	return future.Format("2006-01-02")
}

func GetFutureDateTime(years int, months int, days int) string {
	now := time.Now().UTC()
	future := now.AddDate(years, months, days)
	return future.Format("2006-01-02 15:04:05")
}

func GetFutureTimestamp(years int, months int, days int) int {
	now := time.Now().UTC()
	future := now.AddDate(years, months, days)
	return int(future.Unix())
}

func GetDateTimeFromTimestamp(timeStamp int) string {
	tm := time.Unix(int64(timeStamp), 0).UTC()
	return tm.Format("2006-01-02 15:04:05")
}

func ParseDateInt(dateStr string) (int, error) {
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return -1, nil
	}
	return int(t.Unix()), nil
}

func ParseDateTimeInt(dateTimeStr string) (int, error) {
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}`).MatchString(dateTimeStr) {
		return -1, fmt.Errorf("invalid datetime format")
	}

	t, err := time.Parse("2006-01-02 15:04:05", dateTimeStr)
	if err != nil {
		return -1, nil
	}
	return int(t.Unix()), nil
}
