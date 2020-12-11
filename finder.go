package main

import (
	"errors"
	"fmt"
	"github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var (
	finders       = make(map[string]*Finder)
	defaultFinder = &Finder{}
)

type Finder struct {
	Id              string   `mapstructure:"id"`
	Directory       string   `mapstructure:"directory"` // from user
	Patterns        []string `mapstructure:"patterns"`
	ModifierId      string   `mapstructure:"modifier"`
	PpsLE           float64  `mapstructure:"pps_le"`
	PpsGE           float64  `mapstructure:"pps_ge"`
	PacketCountLe   int64    `mapstructure:"packet_count_le"`
	PacketCountGe   int64    `mapstructure:"packet_count_ge"`
	AvgPacketSizeLE float64  `mapstructure:"avg_packet_size_le"`
	AvgPacketSizeGE float64  `mapstructure:"avg_packet_size_ge"`
	OnlyIpv6        bool     `mapstructure:"only_ipv6"`
	Used            bool     // 是否被某个 job 的 command 使用到

	absDirectory string // auto
	patterns     []*regexp.Regexp
	modifier     *Modifier
	pcaps        []*Pcap

	initialized      bool   //是否已经初始化
	initSucceed      bool   // 初始化是否成功
	initFailReason   string // 初始化失败原因
	createDirOnce    sync.Once
	workingDirectory string

	lock sync.Mutex
}

func (f *Finder) String() string {
	if f.Id != "" {
		return fmt.Sprintf("[Finder %s]", f.Id)
	} else {
		return "[Finder]"
	}
}

func (f *Finder) init() error {
	var err error = nil
	if !f.initialized {
		f.createDirOnce.Do(func() {
			f.workingDirectory = filepath.Join(config.workingDirectory, "finder-"+f.Id)
			err = os.MkdirAll(f.workingDirectory, os.ModePerm)
			if err != nil {
				f.initFailReason = err.Error()
			}
			f.initialized = true
			f.initSucceed = err == nil
		})
	} else if !f.initSucceed {
		err = errors.New(f.initFailReason)
	}
	return err
}

func (f *Finder) check() error {

	if err := checkId(f.Id); err != nil {
		return err
	}

	if _, ok := finders[f.Id]; ok {
		return errors.New(fmt.Sprintf("duplicate finder id: %s", f.Id))
	}

	if f.Directory == "" {
		return errors.New("directory is empty")
	}

	directory, _ := homedir.Expand(f.Directory)
	absDirectory, _ := filepath.Abs(directory)
	logger.Debugf("%s abs directory is: %s\n", f, absDirectory)

	s, err := os.Stat(absDirectory)
	if err != nil {
		return err
	}
	if !s.IsDir() {
		return errors.New(fmt.Sprintf("directory \"%s\" does not exists!", f.Directory))
	}
	f.absDirectory = absDirectory

	if f.ModifierId == "" {
		f.ModifierId = "default"
	}

	modifier, ok := modifiers[f.ModifierId]
	if !ok {
		return errors.New(fmt.Sprintf("modifier \"%s\" not exists", f.ModifierId))
	}
	f.modifier = modifier

	// TODO 检测 pattern 是否重复, 不过也不是很必要
	if f.Patterns != nil {
		f.patterns = make([]*regexp.Regexp, 0)
		for i, pattern := range f.Patterns {
			if pattern == "" {
				return errors.New(fmt.Sprintf("pattern at index %d is empty", i))
			}

			if pattern[len(pattern)-1:] != "*" {
				pattern = pattern + "*"
			}
			pattern = "(?i)^" + pattern + "$"
			pattern = strings.ReplaceAll(pattern, "*", ".*")

			p, err := regexp.Compile(pattern)
			if err != nil {
				return errors.New(fmt.Sprintf("pattern at index %d is invalid: %s", i, err))
			}
			f.patterns = append(f.patterns, p)
		}
	}

	if f.PpsLE < 0 {
		return errors.New("pps_le can not < 0")
	}
	if f.PpsGE < 0 {
		return errors.New("pps_ge can not < 0")
	}
	if f.PpsLE > 0 && f.PpsGE > 0 && f.PpsGE < f.PpsLE {
		return errors.New("pps_ge can not < pps_le")
	}

	if f.PacketCountLe < 0 {
		return errors.New("packet_count_le can not < 0")
	}
	if f.PacketCountGe < 0 {
		return errors.New("packet_count_ge can not < 0")
	}
	if f.PacketCountLe > 0 && f.PacketCountGe > 0 && f.PacketCountGe < f.PacketCountLe {
		return errors.New("packet_count_ge can not < packet_count_le")
	}

	if f.AvgPacketSizeLE < 0 {
		return errors.New("avg_packet_size_le can not < 0")
	}
	if f.AvgPacketSizeGE < 0 {
		return errors.New("avg_packet_size_ge can not < 0")
	}
	if f.AvgPacketSizeLE > 0 && f.AvgPacketSizeGE > 0 && f.AvgPacketSizeGE < f.AvgPacketSizeLE {
		return errors.New("avg_packet_size_ge can not < avg_packet_size_le")
	}

	return nil
}

// callback for os.Walk
func (f *Finder) loadFromPath(path string, info os.FileInfo, err error) error {
	if err != nil {
		logger.Warnln(fmt.Sprintf("%s errer when access %s", f, path))
		return nil
	}

	if info.IsDir() {
		return nil
	}

	file := &File{
		path:   path,
		finder: f,
		info:   info,
	}
	file.parse()
	pcap := &Pcap{
		file: file,
	}

	if err := file.isValidPcapSuffix(); err != nil {
		pcap.showWhy("invalid suffix")
		return nil
	}

	if f.patterns != nil && len(f.patterns) > 0 {
		match := false
		for _, p := range f.patterns {
			match = p.MatchString(file.relativePath)
			if match {
				break
			}
		}
		if !match {
			pcap.showWhy("pattern not match")
			return nil
		}
	}

	err = pcap.init()
	if err != nil {
		pcap.showWhy(fmt.Sprintf("init info failed: %s", err))
		return nil
	}

	if f.PpsLE > 0 {
		if (pcap.info.error & PCAP_INFO_ERR_AVG_PACKET_RATE) != 0 {
			pcap.showWhy(fmt.Sprintf("errors when parse pps: %s", pcap.info.AvgPacketRate))
			return nil
		}
		if pcap.info.avgPacketRate > f.PpsLE {
			pcap.showWhy(fmt.Sprintf("pps value %f greater than limit %f", pcap.info.avgPacketRate, f.PpsLE))
			return nil
		}
	}

	if f.PpsGE > 0 {
		if (pcap.info.error & PCAP_INFO_ERR_AVG_PACKET_RATE) != 0 {
			pcap.showWhy(fmt.Sprintf("errors when parse pps: %s", pcap.info.AvgPacketRate))
			return nil
		}
		if pcap.info.avgPacketRate < f.PpsGE {
			pcap.showWhy(fmt.Sprintf("pps value %f less than limit %f", pcap.info.avgPacketRate, f.PpsGE))
			return nil
		}
	}


	if f.PacketCountLe > 0 {
		if (pcap.info.error & PCAP_INFO_ERR_PACKET_COUNT) != 0 {
			pcap.showWhy(fmt.Sprintf("errors when parse number of packets: %s", pcap.info.PacketCount))
			return nil
		}
		if pcap.info.packetCount > f.PacketCountLe {
			pcap.showWhy(fmt.Sprintf("packet count value %d greater than limit %d", pcap.info.packetCount, f.PacketCountLe))
			return nil
		}
	}

	if f.PacketCountGe > 0 {
		if (pcap.info.error & PCAP_INFO_ERR_PACKET_COUNT) != 0 {
			pcap.showWhy(fmt.Sprintf("errors when parse number of packets: %s", pcap.info.PacketCount))
			return nil
		}
		if pcap.info.packetCount < f.PacketCountGe {
			pcap.showWhy(fmt.Sprintf("packet count value %d less than limit %d", pcap.info.packetCount, f.PacketCountGe))
			return nil
		}
	}

	if f.AvgPacketSizeLE > 0 {
		if (pcap.info.error & PCAP_INFO_ERR_AVG_PACKET_SIZE) != 0 {
			pcap.showWhy(fmt.Sprintf("errors when parse avg packet size: %s", pcap.info.AvgPacketSize))
			return nil
		}
		if pcap.info.avgPacketSize > f.AvgPacketSizeLE {
			pcap.showWhy(fmt.Sprintf("avg packet size value %f greater than limit %f", pcap.info.avgPacketSize, f.AvgPacketSizeLE))
			return nil
		}
	}

	if f.AvgPacketSizeGE > 0{
		if (pcap.info.error & PCAP_INFO_ERR_AVG_PACKET_SIZE) != 0 {
			pcap.showWhy(fmt.Sprintf("errors when parse avg packet size: %s", pcap.info.AvgPacketSize))
			return nil
		}
		if pcap.info.avgPacketSize < f.AvgPacketSizeGE {
			pcap.showWhy(fmt.Sprintf("avg packet size value %f less than limit %f", pcap.info.avgPacketSize, f.AvgPacketSizeGE))
			return nil
		}
	}

	if f.OnlyIpv6 && !pcap.file.finder.modifier.KeepIp && !pcap.hasIPv6 {
		pcap.showWhy(fmt.Sprintf("not contains ipv6 packet"))
		return nil
	}

	// 符合要求, 追加到 pcaps 列表中
	f.lock.Lock()
	f.pcaps = append(f.pcaps, pcap)
	f.lock.Unlock()

	return nil
}
