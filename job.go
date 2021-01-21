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
		if contains(config.SelectedJobs, j.Id) || contains(config.SelectedJobs, "all") {
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
			Id:     "bro",
			Name:   "default job for bro",
			Enable: true,
			Commands: []*Command{
				{
					Name:      "bro",
					Vars:      map[string]interface{}{
						"bro": "/usr/local/bro/bin/bro",
						"bro_config": "/opt/bro-scripts/tophant.entrypoint.bro",
					},
					Command:   "cd {{.FinderDirectory}} && {{.bro}} -r {{.RelativePath}} -C {{.bro_config}}",
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
					Vars:      map[string]interface{}{
						"suricata": "/usr/local/suricata/bin/suricata",
						"suricata_config": "/usr/local/suricata/etc/suricata/suricata.yaml",
					},
					Command:   "cd {{.FinderDirectory}} && {{.suricata}} -c {{.suricata_config}} -r {{.RelativePath}} -k none --runmode autofp",
				},
			},
			FinderId: defaultFinder.Id,
		},
		{
			Id:     "new-suricata",
			Name:   "default job for new suricata",
			Enable: false,
			Commands: []*Command{
				{
					Name:      "suricata",
					Vars:      map[string]interface{}{
						"suricata": "/opt/suricata/bin/suricata",
						"suricata_config": "/opt/suricata/etc/suricata/suricata.yaml",
					},
					Command:   "cd {{.FinderDirectory}} && {{.suricata}} -c {{.suricata_config}} -r {{.RelativePath}} -k none --runmode autofp",
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
					Vars:      map[string]interface{}{
						"moloch": "/data/moloch/bin/moloch-capture",
						"moloch_config": "/data/moloch/etc/config.ini",
					},
					Command:   "cd {{.FinderDirectory}} && {{.moloch}} --insecure -c {{.moloch_config}} -r {{.RelativePath}}",
				},
			},
			FinderId: defaultFinder.Id,
		},
	}
}

func fastCopyJob(directory string) *Job {
	return &Job{
		Id:     "fast-copy",
		Name:   "fast-copy",
		Enable: false,
		Commands: []*Command{
			{
				Name:      "create dst dir",
				Type:      "shell",
				Command:   fmt.Sprintf("mkdir -p %s", directory),
			},
			{
				Name:      "copy modified pcap",
				Command:   fmt.Sprintf("cd %s && mkdir -p {{.RelativeDirectory}} && cp -f {{.Path}} {{.RelativeDirectory}}", directory),
			},
		},
		FinderId: defaultFinder.Id,
	}
}
