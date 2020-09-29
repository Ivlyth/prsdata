package main

import (
	"errors"
	"fmt"
	"time"
)

type Command struct {
	Index int

	Name      string        `mapstructure:"name"`
	Command   string        `mapstructure:"command"`
	Directory string        `mapstructure:"directory"`
	Type      string        `mapstructure:"type"` // shell or pcap, default is pcap
	Timeout   time.Duration `mapstructure:"timeout"`
	FinderId  string        `mapstructure:"finder"` // if not provide, use Job's

	job    *Job
	finder *Finder
}

func (c *Command) String() string {
	if c.Name != "" {
		return fmt.Sprintf("%s [Command %s]", c.job, c.Name)
	}
	return fmt.Sprintf("%s [Command at index %d]", c.job, c.Index)
}

func (c *Command) check() error {

	if c.Name == "" {
		return errors.New("must have a human readable name")
	}

	if c.Command == "" {
		return errors.New("command can not be empty")
	}

	if c.Type == "" {
		c.Type = "pcap"
	}

	if c.Type != "shell" && c.Type != "pcap" {
		return errors.New(fmt.Sprintf("unsupported command type: %s, currently only pcap and shell support", c.Type))
	}

	if c.FinderId == "" {
		c.FinderId = c.job.FinderId
		c.finder = c.job.finder
	} else {
		finder, ok := finders[c.FinderId]
		if !ok {
			return errors.New(fmt.Sprintf("unknown finder id: %s", c.FinderId))
		}
		c.finder = finder
	}

	if c.job.Enable {
		c.finder.modifier.Used = true
		c.finder.Used = true
	}

	if c.Timeout == 0 {
		c.Timeout = config.CommandTimeout
	}

	return nil
}
