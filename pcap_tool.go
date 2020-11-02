package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var pcapTool = &PcapTool{}

type PcapTool struct {
	Bash       string `mapstructure:"bash"`
	Capinfos   string `mapstructure:"capinfos"`
	Editcap    string `mapstructure:"editcap"`
	Tcpdump    string `mapstructure:"tcpdump"`
	Tcprewrite string `mapstructure:"tcprewrite"`
	Tcpprep    string `mapstructure:"tcpprep"`
}

func (p *PcapTool) String() string {
	return "[Pcap Tool]"
}

func (p *PcapTool) check() error {
	for tool, path := range map[string]*string{
		"bash":       &p.Bash,
		"capinfos":   &p.Capinfos,
		"editcap":    &p.Editcap,
		"tcpdump":    &p.Tcpdump,
		"tcprewrite": &p.Tcprewrite,
		"tcpprep":    &p.Tcpprep,
	} {
		if !filepath.IsAbs(*path) {
			// find in path
			absPath, err := exec.LookPath(*path)
			if err != nil {
				return errors.New(fmt.Sprintf("command %s not found in $PATH", tool))
			}
			// update to abs
			*path = absPath
		}
		s, err := os.Stat(*path)
		if os.IsNotExist(err) {
			return errors.New(fmt.Sprintf("command %s not found at %s", tool, *path))
		}
		if s.IsDir() {
			return errors.New(fmt.Sprintf("command %s not a regular file", tool))
		}
	}
	return nil
}

func (p *PcapTool) adjustTime(src, dst string, timeOffset int64) *ExecResult {

	return execShellCommand(fmt.Sprintf("%s -t %d %s %s", p.Editcap, timeOffset, src, dst), config.CommandTimeout)
}

func (p *PcapTool) generateCache(src, dst string, timeout time.Duration) *ExecResult {
	if timeout == 0 {
		timeout = config.CommandTimeout
	}
	return execShellCommand(fmt.Sprintf("%s -a client --pcap=%s --cachefile=%s --nonip", p.Tcpprep, src, dst), timeout)
}

func (p *PcapTool) modifyIp(src, dst, cache, endpoints string, timeout time.Duration) *ExecResult {
	if timeout == 0 {
		timeout = config.CommandTimeout
	}

	cmd := fmt.Sprintf("%s --fixcsum --infile=%s --outfile=%s --skipbroadcast --cachefile=%s --endpoints=%s",
		p.Tcprewrite, src, dst, cache, endpoints)
	return execShellCommand(cmd, timeout)
}

func (p *PcapTool) filterIPv6(src, dst string, timeout time.Duration) *ExecResult {
	if timeout == 0 {
		timeout = config.CommandTimeout
	}
	return execShellCommand(fmt.Sprintf("%s -r %s -w %s -c 1 ip6", p.Tcpdump, src, dst), timeout)
}