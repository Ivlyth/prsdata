package main

import (
	logger "github.com/sirupsen/logrus"
)

var LogTimeFormat = "2006-01-02 15:04:05.000"
var DirTimeFormat = "2006_01_02_15_04_05"

func init() {
	logger.SetFormatter(&logger.TextFormatter{
		TimestampFormat:        LogTimeFormat, //
		DisableLevelTruncation: true,
		//PadLevelText: true,
		FullTimestamp: true,
	})
}
