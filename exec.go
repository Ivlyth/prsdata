package main

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	logger "github.com/sirupsen/logrus"
)

type ExecResult struct {
	command string
	output  string
	err     error
	succeed bool
}

func (c *ExecResult) String() string {
	if c.succeed {
		return fmt.Sprintf("[Succeed] %s", c.output)
	} else {
		if c.output != "" {
			return fmt.Sprintf("[Failed] %s", c.output)
		} else {
			return fmt.Sprintf("[Failed] %s", c.err)
		}
	}
}

func execRealCommand(realCommand *RealCommand) *ExecResult {
	if realCommand.command.Type == "shell" {
		return execCommand(realCommand.command)
	} else {
		pcapPath, err := realCommand.pcap.new()
		if err != nil {
			return errResult(err)
		}
		f := File{
			path:   pcapPath,
			finder: realCommand.pcap.file.finder,
		}
		f.parse()
		defer f.delete()

		pcapContext := &PcapContext{
			WorkingDirectory:  config.workingDirectory,
			FinderDirectory:   realCommand.pcap.file.finder.workingDirectory,
			PcapDirectory:     realCommand.pcap.workingDirectory,
			RelativeDirectory: f.relativeDirectory,
			RelativePath:      f.relativePath,
			Path:              pcapPath,
			BaseName:          f.baseName,
			Name:              f.name,
			Ext:               f.ext,
			HasIpv6:           realCommand.pcap.hasIPv6,
			PacketCount:       realCommand.pcap.info.packetCount,
		}

		renderedCommand, err := pcapContext.render(realCommand.command)
		if err != nil {
			return errResult(err)
		}

		result := execShellCommand(renderedCommand, realCommand.command.Timeout)
		return result
	}
}

func execCommand(command *Command) *ExecResult {
	result := execShellCommand(command.Command, command.Timeout)
	return result
}

func execShellCommand(command string, timeout time.Duration) *ExecResult {

	cmd := exec.Command(pcapTool.Bash, "-c", command)
	sysAttr := &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.SysProcAttr = sysAttr

	if config.ShowCommand {
		logger.Debugln(fmt.Sprintf("executing: %s (with timeout %s)", command, timeout))
	}

	reaper := time.After(timeout)
	processFinished := make(chan struct{})

	isTimeout := false

	go func() {
		select {
		case <-reaper:
			// timeout
			isTimeout = true
			// kill process use pkill
			_ = syscall.Kill(-cmd.Process.Pid, 9)
		case <-processFinished:

		}
	}()

	bytes, err := cmd.CombinedOutput()
	close(processFinished)

	output := string(bytes)

	if isTimeout {
		err = errors.New("timeout")
	}

	if config.ShowCommandStdout {
		logger.Debugln(fmt.Sprintf("executing: %s (with timeout %s)\n----------------------- output is: --------------------\n%s", command, timeout, output))
	}

	return &ExecResult{
		command: command,
		output:  output,
		err:     err,
		succeed: err == nil,
	}
}

func errResult(err error) *ExecResult {
	return &ExecResult{
		command: "",
		output:  "",
		err:     err,
		succeed: false,
	}
}
