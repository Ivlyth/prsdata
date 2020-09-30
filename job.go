package main

import (
	"errors"
	"fmt"
)

var (
	jobs         = make(map[string]*Job)
	selectedJobs = make(map[string]*Job)
)

type Job struct {
	Id       string     `mapstructure:"id"`
	Name     string     `mapstructure:"name"`
	Commands []*Command `mapstructure:"commands"`
	Enable   bool       `mapstructure:"enable"`

	FinderId string `mapstructure:"finder"`

	finder *Finder
}

func (j *Job) String() string {
	if j.Name != "" {
		return fmt.Sprintf("[Job %s]", j.Name)
	} else if j.Id != "" {
		return fmt.Sprintf("[Job %s]", j.Id)
	}
	return "[Job]"
}

func (j *Job) check() error {
	if err := checkId(j.Id); err != nil {
		return err
	}

	if _, ok := jobs[j.Id]; ok {
		return errors.New(fmt.Sprintf("duplicate jbo id: %s", j.Id))
	}

	if config.SelectedJobs != nil && len(config.SelectedJobs) > 0 {
		if contains(config.SelectedJobs, j.Id) {
			j.Enable = true
		} else {
			j.Enable = false
		}
	}
	if j.Enable {
		selectedJobs[j.Id] = j
	}

	if j.Commands == nil || len(j.Commands) == 0 {
		return errors.New("commands can not be empty")
	}

	if j.Name == "" {
		return errors.New("must have a human readable name")
	}

	if j.FinderId == "" {
		j.FinderId = "default"
	}

	finder, ok := finders[j.FinderId]
	if !ok {
		return errors.New(fmt.Sprintf("unknown finder id: %s", j.FinderId))
	}
	j.finder = finder

	for i, c := range j.Commands {
		if c == nil {
			return errors.New(fmt.Sprintf("command at index %d is null", i))
		}
		c.Index = i
		c.job = j
		check(c)
	}

	return nil
}

func defaultJobs() []*Job {
	return []*Job{
		{
			Id:     "zeek",
			Name:   "default job for zeek",
			Enable: true,
			Commands: []*Command{
				{
					Name:      "zeek",
					Command:   "cd {{.FinderDirectory}} && /opt/zeek/bin/zeek -r {{.RelativePath}} -C /opt/zeek-scripts/tophant.entrypoint.zeek",
				},
			},
			FinderId: defaultFinder.Id,
		},
		{
			Id:     "suricata",
			Name:   "default job for suricata",
			Enable: true,
			Commands: []*Command{
				{
					Name:      "suricata",
					Command:   "cd {{.FinderDirectory}} && /opt/suricata/bin/suricata -c /opt/suricata/etc/suricata/suricata.yaml -r {{.RelativePath}} -k none --runmode autofp",
				},
			},
			FinderId: defaultFinder.Id,
		},
		{
			Id:     "moloch",
			Name:   "default job for moloch",
			Enable: false,
			Commands: []*Command{
				{
					Name:      "moloch",
					Command:   "cd {{.FinderDirectory}} && /data/moloch/bin/moloch-capture --insecure -c /data/moloch/etc/config.ini -r {{.RelativePath}}",
				},
			},
			FinderId: defaultFinder.Id,
		},
	}
}