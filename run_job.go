package main

import (
	"fmt"
	"github.com/panjf2000/ants/v2"
	"sync"
)

type RealJob struct {
	round int
	job   *Job
	pool  *ants.PoolWithFunc
}

func (r *RealJob) String() string {
	return fmt.Sprintf("[%d/%d]", r.round, config.TestTimes)
}

func runCommands(realJob *RealJob) {

	// 按照执行次数要求反复创建任务
	totalCount := 0
	for _, command := range realJob.job.Commands {
		g := sync.WaitGroup{}

		if command.Type == "shell" {
			totalCount = 1
		} else { // pcap
			totalCount = len(command.finder.pcaps)
		}

		round := 0
		if RUNNING {
			if command.Type == "shell" {
				round++
				realCommand := &RealCommand{
					round:   round,
					total:   totalCount,
					command: command,
					realJob: realJob,
					g:       &g,
				}
				g.Add(1)
				_ = realJob.pool.Invoke(realCommand)
			} else {
				// pcap
				for _, pcap := range command.finder.pcaps {

					if !RUNNING {
						return
					}

					round++

					realCommand := &RealCommand{
						round:   round,
						total:   totalCount,
						command: command,
						pcap:    pcap,
						realJob: realJob,
						g:       &g,
					}
					g.Add(1)
					_ = realJob.pool.Invoke(realCommand)
				}
			}
		}
		g.Wait() // commands in the same job runs sequentially
	}
}
