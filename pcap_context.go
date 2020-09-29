package main

import (
	"bytes"
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
}

var samplePcapContext = PcapContext{
	WorkingDirectory: "/path/to/working/directory",
	FinderDirectory:  "/path/to/working/directory/finder/",
	PcapDirectory:    "/path/to/working/directory/finder/pcap/",
	Path:             "/path/to/working/directory/finder/pcap/test.pcap",
}

func (p *PcapContext) render(s string) (string, error) {
	t, _ := template.New("pcap").Parse(s)
	buf := bytes.Buffer{}
	err := t.Execute(&buf, *p)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
