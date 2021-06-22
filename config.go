package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	config = &Config{}
)

type Config struct {
	ConcurrencyJobs     int           `mapstructure:"concurrency_jobs"`
	ConcurrencyCommands int           `mapstructure:"concurrency_commands"`
	TestTimes           int           `mapstructure:"test_times"`
	Duration            time.Duration `mapstructure:"duration"`
	CommandTimeout      time.Duration `mapstructure:"command_timeout"`
	TemporaryDirectory  string        `mapstructure:"temporary_directory"`
	SelectedJobs        []string      `mapstructure:"jobs"`

	AsDaemon bool   `mapstructure:"daemon"`
	Pingback string `mapstructure:"pingback"`

	FastCopyDirectory string            `mapstructure:"fast_copy"`
	FastMergePcapPath string            `mapstructure:"fast_merge"`
	Vars              map[string]string `mapstructure:"vars"`

	KeepData           bool `mapstructure:"keep_data"`
	Debug              bool `mapstructure:"debug"`
	JustShowJobs       bool `mapstructure:"just_show_jobs"`
	JustShowPcaps      bool `mapstructure:"just_show_pcaps"`
	ShowCommand        bool `mapstructure:"show_command"`
	ShowCommandStdout  bool `mapstructure:"show_stdout"`
	ShowWhyNotLoadPcap bool `mapstructure:"show_why"`

	ProfilePort uint16 `mapstructure:"profile"`
	Quiet       bool   `mapstructure:"quiet"`

	workingDirectory string
	daemonLogPath    string
}

func (c *Config) String() string {
	return "[Config]"
}

func (c *Config) check() error {
	if c.ConcurrencyJobs <= 0 {
		return errors.New("concurrency jobs can't be zero")
	}
	if c.ConcurrencyCommands <= 0 {
		return errors.New("concurrency commands can't be zero")
	}
	if c.TestTimes <= 0 {
		return errors.New("test times can't be zero")
	}
	if c.CommandTimeout <= 0 {
		return errors.New("default command timeout can't be zero")
	}

	absTemporaryDirectory, _ := filepath.Abs(c.TemporaryDirectory)
	if err := os.MkdirAll(absTemporaryDirectory, os.ModePerm); err != nil {
		return errors.New(fmt.Sprintf("error when create temporary directory: %s", err))
	}

	c.workingDirectory = filepath.Join(absTemporaryDirectory, fmt.Sprintf("prsdata-%s-%d", startTime.Format(DirTimeFormat), os.Getpid()))
	if err := os.MkdirAll(c.workingDirectory, os.ModePerm); err != nil {
		return errors.New(fmt.Sprintf("error when create working directory: %s", err))
	}
	c.daemonLogPath = filepath.Join(c.workingDirectory, "prsdata.log")
	return nil
}
