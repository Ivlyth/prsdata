package main

import (
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
	logger "github.com/sirupsen/logrus"
)

var (
	RUNNING = false

	cleanOnce sync.Once
)

func run() {
	// just show pcaps 的前提是有被选中的 job, 基于 job 的 finder 来展示 pcap 列表
	if config.Pingback != "" {
		err := startPingback(config.Pingback)
		if err != nil {
			logger.Errorln(fmt.Sprintf("error when fork as daemon: %s", err))
			terminate()
		}
		// change logger's output to the given file
		logFile, err := os.OpenFile(config.daemonLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, os.ModePerm)
		if err != nil {
			logger.Errorln(fmt.Sprintf("error when open daemon log file: %s", err))
			terminate()
		}
		logger.SetOutput(logFile)
		logger.Infoln(fmt.Sprintf("redirect output to %s", config.daemonLogPath))
	}

	if len(selectedJobs) == 0 {
		logger.Errorln("no job selected !!!")
		return
	}

	/*
		并发加载 finder 的 pcap 列表, 然后决定是否仅展示 Pcap 列表
	*/
	loadPcaps()

	if config.JustShowJobs {
		for _, job := range jobs {
			logger.Infoln(fmt.Sprintf("%s id is %s, using finder %s, which has %d pcaps", job, job.Id, job.finder, len(job.finder.pcaps)))
		}
		exit(0)
	}

	if config.JustShowPcaps {
		exit(0)
	}

	if config.AsDaemon && config.Pingback == "" { // parent
		err := startDaemon()
		if err != nil {
			logger.Errorln(fmt.Sprintf("error when fork as daemon: %s", err))
			terminate()
		}
		return
	}

	if config.Duration > 0 {
		go timeoutChecker()
	}

	runJobs()
}

func runJobs() {
	defer cleanup(0)
	RUNNING = true

	ConcurrencyJobs := int(math.Min(float64(config.ConcurrencyJobs), float64(config.TestTimes*(len(selectedJobs)))))
	jobsGroup := sync.WaitGroup{}

	pool, _ := ants.NewPoolWithFunc(ConcurrencyJobs, func(i interface{}) {
		defer jobsGroup.Done()
		realJob := i.(*RealJob)
		defer realJob.pool.Release()

		if !RUNNING {
			return
		}

		runCommands(realJob)
	})
	defer pool.Release()

	// 按照执行次数要求反复创建任务
	for t := 0; t < config.TestTimes; t++ {
		for _, job := range selectedJobs {
			if RUNNING {

				jobPool, _ := ants.NewPoolWithFunc(config.ConcurrencyCommands, func(i interface{}) {
					realCommand := i.(*RealCommand)
					defer realCommand.g.Done()
					realCommand.run()
				})
				realJob := &RealJob{
					round: t + 1,
					job:   job,
					pool:  jobPool,
				}
				jobsGroup.Add(1)
				_ = pool.Invoke(realJob)
			}
		}
	}
	jobsGroup.Wait()
}

func timeoutChecker() {
	logger.Infoln(fmt.Sprintf("run time checker start to control the run time under %s", config.Duration))
	time.Sleep(config.Duration)
	logger.Warnf("timeout, force exit")
	terminate()
}

func cleanup(waiting int) {
	cleanOnce.Do(func() {
		running := RUNNING
		RUNNING = false

		if config.workingDirectory != "" {
			if config.KeepData {
				logger.Warnln(fmt.Sprintf("as reminder, your data under %s, please remember to remove it after use", config.workingDirectory))
				return
			}
			if running && waiting != 0 {
				logger.Warnln("waiting 3secs to cleanup")
				time.Sleep(3 * time.Second)
			}
			logger.Infoln(fmt.Sprintf("removing temporary working directory: %s", config.workingDirectory))
			_ = os.RemoveAll(config.workingDirectory)
		}
	})
}
