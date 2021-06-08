package main

import (
	"fmt"
	logger "github.com/sirupsen/logrus"
	"net/http"
	_ "net/http/pprof"
	"os"
)

func startProfileServer(port uint16) {
	go func() {
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), nil)
		if err != nil {
			logger.Errorln(fmt.Sprintf("error when start pprof server on local port %d: %s", port, err))
			os.Exit(1)
		}
		logger.Infoln(fmt.Sprintf("pprof http server listen on port %d", port))
	}()
}
