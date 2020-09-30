// +build darwin

package main

import (
	"fmt"
	"time"
)

func (p *PcapTool) getPcapInfo(src string, timeout time.Duration) *ExecResult {
	if timeout == 0 {
		timeout = config.CommandTimeout
	}
	return execShellCommand(fmt.Sprintf("%s -K -EMHS -uaezxcsd %s", p.Capinfos, src), timeout)
}
