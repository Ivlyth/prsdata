package main

import (
	"fmt"
	"github.com/panjf2000/ants/v2"
	logger "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func loadPcaps() {
	pool, _ := ants.NewPool(20) // fixed pool
	defer pool.Release()

	wg := sync.WaitGroup{}

	start := time.Now()

	for _, finder := range finders {
		if !finder.Used {
			// 忽略未使用的 finder
			continue
		}

		err := finder.init()
		if err != nil {
			logger.Errorln(fmt.Sprintf("%s init failed: %s", finder, err))
			errorHappened = true
			terminate()
		}

		logger.Infoln(fmt.Sprintf("%s loading pcaps", finder))

		finder.pcaps = make([]*Pcap, 0)
		_ = filepath.Walk(finder.absDirectory, func(path string, info os.FileInfo, err error) error {
			wg.Add(1)
			_ = pool.Submit(func() {
				defer wg.Done()
				_ = finder.loadFromPath(path, info, err)
			})
			return nil
		})

		wg.Wait()

		if len(finder.pcaps) == 0 {
			logger.Errorln(fmt.Sprintf("%s load 0 pcaps", finder))
			errorHappened = true
			terminate()
		}

		logger.Infoln(fmt.Sprintf("%s load %d pcaps", finder, len(finder.pcaps)))
		if config.JustShowPcaps {
			for _, pcap := range finder.pcaps {
				logger.Infoln(fmt.Sprintf("%s", pcap))
			}
		}
	}

	end := time.Now()
	duration := end.Sub(start)
	logger.Infoln(fmt.Sprintf("load pcaps totally use: %s", duration))
}
