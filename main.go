package main

import (
	"fmt"
	logger "github.com/sirupsen/logrus"
	"time"
)

var (
	startTime time.Time
)

func init() {
	startTime = time.Now()
}

func main() {
	defer func() {
		logger.Infoln(fmt.Sprintf("done. totally use: %s", time.Now().Sub(startTime)))
	}()

	go handleSignal()

	rootCmd.Execute()
}
