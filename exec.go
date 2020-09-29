package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
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
		}

		renderedCommand, err := pcapContext.render(realCommand.command.Command)
		if err != nil {
			return errResult(err)
		}

		renderDirectory := ""
		if realCommand.command.Directory != "" {
			renderDirectory, err = pcapContext.render(realCommand.command.Directory)
			if err != nil {
				return errResult(err)
			}
		} else {
			renderDirectory = pcapContext.FinderDirectory
		}

		result := execShellCommand(renderedCommand, renderDirectory, realCommand.command.Timeout)
		return result
	}
}

func execCommand(command *Command) *ExecResult {
	result := execShellCommand(command.Command, command.Directory, command.Timeout)
	return result
}

func execShellCommand(command, directory string, timeout time.Duration) *ExecResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if config.ShowCommand {
		logger.Debugln(fmt.Sprintf("executing: %s (with timeout %s)", command, timeout))
	}

	fields := strings.Fields(command)
	//cmd := exec.CommandContext(ctx, pcapTool.Bash, "-c", command)
	cmd := exec.CommandContext(ctx, fields[0], fields[1:]...)
	if directory != "" {
		cmd.Dir = directory
	}

	out, err := cmd.CombinedOutput()

	output := ""

	if ctx.Err() == context.DeadlineExceeded {
		err = errors.New("timeout")
		if out != nil {
			output = string(out)
		}
	} else if err != nil {
		output = string(out)
		err = errors.New(output)
	} else {
		output = string(out)
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
