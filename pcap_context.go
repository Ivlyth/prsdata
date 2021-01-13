package main

import (
	"bytes"
	"encoding/json"
	"html/template"
)

// TODO 更新 pcap context, 以及添加对命令的检测
type PcapContext struct {
	WorkingDirectory  string
	FinderDirectory   string
	PcapDirectory     string
	RelativeDirectory string
	RelativePath      string
	Path              string // full pcap file path
	BaseName          string
	Name              string
	Ext               string
	HasIpv6           bool
	PacketCount       int64
}

var samplePcapContext = PcapContext{
	WorkingDirectory: "/path/to/working/directory",
	FinderDirectory:  "/path/to/working/directory/finder/",
	PcapDirectory:    "/path/to/working/directory/finder/pcap/",
	Path:             "/path/to/working/directory/finder/pcap/test.pcap",
}

func (p *PcapContext) render(command *Command) (string, error) {
	s := command.Command
	t, _ := template.New("pcap").Parse(s)
	buf := bytes.Buffer{}

	contextBuf, _ := json.Marshal(*p)
	context := map[string]interface{}{}

	// merge from command vars first
	if command.Vars != nil {
		for k, v := range command.Vars {
			context[k] = v
		}
	}

	// then merge from user input
	for k, v := range config.Vars {
		context[k] = v
	}

	pcapContext := map[string]interface{}{}
	_ = json.Unmarshal(contextBuf, &pcapContext)
	for k, v := range pcapContext {
		context[k] = v
	}

	err := t.Execute(&buf, context)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
