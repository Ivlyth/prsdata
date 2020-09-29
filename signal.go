package main

import (
	logger "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	continuousCancelCount int
	lastCancel            time.Time
)

func handleSignal() {
	sigchan := make(chan os.Signal, 10)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case s := <-sigchan:
			if s == syscall.SIGINT || s == syscall.SIGTERM {
				RUNNING = false
				if continuousCancelCount == 0 {
					continuousCancelCount++
					lastCancel = time.Now()
					logger.Warnf("canceled by user, try to wait most %s for running commands\n", config.CommandTimeout)
					go waitMost(config.CommandTimeout)
				} else {
					if time.Now().Sub(lastCancel) < time.Second {
						logger.Warnln("force exit by twice CTRL+C within 1sec")
						terminate()
					} else {
						logger.Warnln("CTRL+C twice times within 1sec can force exit")
						continuousCancelCount = 1 // reset to 1
						lastCancel = time.Now()
					}
				}
			}
		}
	}
}

func waitMost(t time.Duration) {
	killer := time.NewTimer(t)
	<-killer.C
	logger.Errorf("force exit after %s\n", t)
	terminate()
}
