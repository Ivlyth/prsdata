package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path"
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
	Id               string   `mapstructure:"id"`
	Directory        string   `mapstructure:"directory"` // from user
	Patterns         []string `mapstructure:"patterns"`
	Tags             []string `mapstructure:"tags"`
	ModifierId       string   `mapstructure:"modifier"`
	PpsLE            float64  `mapstructure:"pps_le"`
	PpsGE            float64  `mapstructure:"pps_ge"`
	PacketCountLe    int64    `mapstructure:"packet_count_le"`
	PacketCountGe    int64    `mapstructure:"packet_count_ge"`
	AvgPacketSizeLE  float64  `mapstructure:"avg_packet_size_le"`
	AvgPacketSizeGE  float64  `mapstructure:"avg_packet_size_ge"`
	OnlyIpv6         bool     `mapstructure:"only_ipv6"`
	OnlyEthernet     bool     `mapstructure:"only_ethernet"`
	TsharkReadFilter string   `mapstructure:"tshark_read_filter"`
	Used             bool     // 是否被某个 job 的 command 使用到

	absDirectory string // auto
	patterns     []*regexp.Regexp

	tags         [][]string
	pcapTagsInfos []PcapTagsInfo

	modifier     *Modifier
	pcaps        []*Pcap

	initialized      bool   //是否已经初始化
	initSucceed      bool   // 初始化是否成功
	initFailReason   string // 初始化失败原因
	createDirOnce    sync.Once
	workingDirectory string

	lock sync.Mutex
}

type PcapTagsInfo struct {
	Name string   `json:"name"`
	Path string   `json:"path"`
	Tags []string `json:"tags"`

	absPath string
}

func (pti PcapTagsInfo) String() string {
	return fmt.Sprintf("PcapTagsInfo - path:%s, tags: %v", pti.Path, pti.Tags)
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
			defer func() {
				if err != nil {
					f.initFailReason = err.Error()
				}
				f.initSucceed = err == nil
				f.initialized = true
			} ()

			f.workingDirectory = filepath.Join(config.workingDirectory, "finder-"+f.Id)
			err = os.MkdirAll(f.workingDirectory, os.ModePerm)

			if err != nil {
				return
			}
			// load tags info under pcap directory
			if len(f.tags) > 0 {
				if !exists(path.Join(f.absDirectory, "tags.json")) {
					err = errors.New(fmt.Sprintf("can not find file `tags.json`"))
					return
				}

				content, err1 := ioutil.ReadFile(path.Join(f.absDirectory, "tags.json"))
				if err1 != nil {
					err = errors.New(fmt.Sprintf("can not read file `tags.json`: %s", err1))
					return
				}

				var datas []PcapTagsInfo
				err = json.Unmarshal(content, &datas)
				if err != nil {
					err = errors.New(fmt.Sprintf("can not unmarshal content of `tags.json`: %s", err))
					return
				}

				for i, _ := range datas {
					pti := &datas[i]
					if pti.Name == "" {
						err = errors.New(fmt.Sprintf("pcap tags info at index %d invalid: empty name", i))
						return
					}
					if pti.Path == "" {
						err = errors.New(fmt.Sprintf("pcap tags info at index %d invalid: empty path", i))
						return
					}
					if path.IsAbs(pti.Path) {
						err = errors.New(fmt.Sprintf("pcap tags info at index %d invalid: absoulte path", i))
						return
					}
					pti.absPath = path.Join(f.absDirectory, pti.Path)
					if !exists(pti.absPath) {
						err = errors.New(fmt.Sprintf("pcap tags info at index %d invalid: path `%s` not exists", i, path.Join(f.absDirectory, pti.Path)))
						return
					}
					if len(pti.Tags) == 0 {
						err = errors.New(fmt.Sprintf("pcap tags info at index %d invalid: empty tags", i))
						return
					}
				}
				f.pcapTagsInfos = datas
			}
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

			if filepath.IsAbs(pattern) { // abs path used
				absPattern, _ := filepath.Abs(pattern)
				// remove the prefix silently
				if absPattern == f.absDirectory {
					logger.Warnln(fmt.Sprintf("pattern `%s` is the same as finder's directory, ignore it", pattern))
					continue
				}

				// anti /data/.prsdata/pcaps/xff-test  /data/.prsdata/pcaps/xff
				parentDirectory := filepath.Dir(absPattern)
				if strings.HasPrefix(absPattern, f.absDirectory) && strings.HasPrefix(parentDirectory, f.absDirectory) {
					pattern = absPattern[len(f.absDirectory):]
					if pattern[0] == '/' {
						pattern = pattern[1:]
					}
				} else {
					return errors.New(fmt.Sprintf("pattern `%s` detect as a ABS path, but not in the finder's directory", pattern))
				}
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

	if f.Tags != nil {
		f.tags = make([][]string, 0)

		for _, tag := range f.Tags {
			tags := make([][]string, 0)
			for _, tag1 := range strings.Split(tag, " ") {
				tags = append(tags, strings.Split(tag1, ","))
			}
			f.tags = append(f.tags, expandTags(tags...)...)
		}
	}

	//if len(f.tags) > 0 && len(f.patterns) > 0 {
	//	return errors.New("can not use --patterns and --tags together")
	//}

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

func (f *Finder) loadFromPcapTagsInfo(pti *PcapTagsInfo) error {
	info, err := os.Stat(pti.absPath)

	if err != nil {
		logger.Warnln(fmt.Sprintf("%s errer when access pti %s", f, pti.absPath))
		return nil
	}

	if info.IsDir() {
		return nil
	}

	file := &File{
		path:   pti.absPath,
		finder: f,
		info:   info,
		pti:    pti,
	}
	file.parse()
	pcap := &Pcap{
		file: file,
	}
	return f.checkAndLoadPcap(pcap)
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

	return f.checkAndLoadPcap(pcap)
}


func (f *Finder) checkAndLoadPcap(pcap *Pcap) error {
	file := pcap.file
	if err := file.isValidPcapSuffix(); err != nil {
		pcap.showWhy("invalid suffix")
		return nil
	}

	if len(f.patterns) > 0 {
		match := false
		name := file.relativePath
		if file.pti != nil {
			name = file.pti.Name
		}
		for _, p := range f.patterns {
			match = p.MatchString(name)
			if match {
				break
			}
		}
		if !match {
			pcap.showWhy(fmt.Sprintf("pattern not match: %s against %v", name, f.patterns))
			return nil
		}
	}

	if len(f.tags) > 0 {
		match := false
		for _, tags := range f.tags {
			match = allInOthers(tags, file.pti.Tags)
			if match {
				break
			}
		}
		if !match {
			pcap.showWhy(fmt.Sprintf("tags not match: %v against %v", file.pti.Tags, f.tags))
			return nil
		}
	}

	err := pcap.init()
	if err != nil {
		pcap.showWhy(fmt.Sprintf("init info failed: %s", err))
		return nil
	}

	if f.OnlyEthernet && !pcap.info.IsEthernet() {
		pcap.showWhy(fmt.Sprintf("not ethernet encapsulation (%s)", pcap.info.Encapsulation))
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

	if f.AvgPacketSizeGE > 0 {
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