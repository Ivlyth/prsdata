// +build !darwin

package main

import "time"
import "fmt"

func (p *PcapTool) getPcapInfo(src string, timeout time.Duration) *ExecResult {
	if timeout == 0 {
		timeout = config.CommandTimeout
	}
	return execShellCommand(fmt.Sprintf("%s -EMHS -uaezxcsd %s", p.Capinfos, src), timeout)
}
