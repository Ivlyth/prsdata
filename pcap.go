package main

import (
	"errors"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/atomic"
)

type Pcap struct {
	file *File

	initialized    bool   //是否已经初始化
	initSucceed    bool   // 初始化是否成功
	initFailReason string // 初始化失败原因

	createDirOnce    sync.Once
	workingDirectory string

	copyFilePath  string // init 阶段拷贝一份到该目录下利用
	cacheFilePath string // init 阶段生成 cache file
	info          *PcapInfo
	hasIPv6       bool

	counter atomic.Int32
}

func (p *Pcap) String() string {
	if p.info != nil && config.JustShowPcaps {
		return fmt.Sprintf("%s [Pcap-%s] %d packets, %.2f pps, %.2f avg packet size", p.file.finder, p.file.relativePath, p.info.packetCount, p.info.avgPacketRate, p.info.avgPacketSize)
	} else {
		return fmt.Sprintf("%s [Pcap-%s]", p.file.finder, p.file.relativePath)
	}
}

func (p *Pcap) init() error {
	var err error = nil
	if !p.initialized {
		p.createDirOnce.Do(func() {
			defer func() {
				p.initSucceed = err == nil
				p.initialized = true
				if !p.initSucceed {
					p.initFailReason = err.Error()
				}
			}()

			// try init finder
			if !p.file.finder.initialized {
				_ = p.file.finder.init()
			}
			if !p.file.finder.initSucceed {
				err = errors.New(fmt.Sprintf("finder init failed: %s", p.file.finder.initFailReason))
				return
			}

			// get pcap info
			info, err1 := parsePcapInfo(p.file.path)
			if err1 != nil {
				err = err1
				return
			}
			p.info = info

			p.workingDirectory = filepath.Join(p.file.finder.workingDirectory, p.file.relativeDirectory)
			err = os.MkdirAll(p.workingDirectory, os.ModePerm)
			if err != nil {
				return
			}
			// copy to working directory
			p.copyFilePath = filepath.Join(p.workingDirectory, p.file.baseName)
			err = p.file.copyTo(p.copyFilePath)
			if err != nil {
				return
			}

			if p.file.finder.modifier.AdjustTime {
				if (p.info.error & PCAP_INFO_ERR_LAST_PACKET_TIME) != 0 {
					err = errors.New(fmt.Sprintf("errors when parse last packet time: %s", p.info.LastPacketTime))
					return
				}
				dst := filepath.Join(p.workingDirectory, fmt.Sprintf("%s.adjust-time", p.file.name))
				result := pcapTool.adjustTime(p.file.path, dst, p.timeOffset())
				adjf := File{path: dst}
				defer adjf.delete()
				if !result.succeed {
					err = result.err
					return
				}
			}

			if p.file.finder.TsharkReadFilter != "" {
				pcapType := "pcap"
				if p.info.IsPcapNG() {
					pcapType = "pcapng"
				}
				rfFile := filepath.Join(p.workingDirectory, fmt.Sprintf("%s.tshark_rf", p.file.name))
				result := pcapTool.tsharkReadFilter(p.file.path, rfFile, p.file.finder.TsharkReadFilter, pcapType, 0)
				if !result.succeed {
					err = result.err
					return
				}
				info2, err2 := parsePcapInfo(rfFile)
				rff := File{path: rfFile}
				defer rff.delete()
				if err2 != nil {
					err = err2
					return
				}
				if info2.packetCount <= 0 {
					err = errors.New("no packets left after tshark filter")
					return
				}
			}

			if !p.file.finder.modifier.KeepIp {
				// first, generate cache file
				p.cacheFilePath = filepath.Join(p.workingDirectory, fmt.Sprintf("%s.cache", p.file.name))
				result := pcapTool.generateCache(p.file.path, p.cacheFilePath, 0)
				if !result.succeed {
					err = result.err
					return
				}

				ipv6File := filepath.Join(p.workingDirectory, fmt.Sprintf("%s.ipv6", p.file.name))
				result = pcapTool.filterIPv6(p.file.path, ipv6File, 0)
				if !result.succeed {
					err = result.err
					return
				}
				info2, err2 := parsePcapInfo(ipv6File)
				ipv6f := File{path: ipv6File}
				defer ipv6f.delete()
				if err2 != nil {
					err = err2
					return
				}
				p.hasIPv6 = info2.packetCount > 0

				endpoints := p.file.finder.modifier.randomEndPoints(p.hasIPv6)
				modifyIPFile := filepath.Join(p.workingDirectory, fmt.Sprintf("%s.modify-ip", p.file.name))
				result = pcapTool.modifyIp(p.file.path, modifyIPFile, p.cacheFilePath, endpoints, 0)
				modifyf := File{path: modifyIPFile}
				defer modifyf.delete()
				if !result.succeed {
					err = errors.New(fmt.Sprintf("can not modify ip: %s", result.err))
					return
				}
			}
		})
	} else if !p.initSucceed {
		err = errors.New(p.initFailReason)
	}
	return err
}

func (p *Pcap) timeOffset() int64 {
	adjustment := time.Now().Sub(p.info.lastPacketTime) - p.file.finder.modifier.TimeOffset
	return int64(adjustment) / int64(time.Second)
}

func (p *Pcap) new() (string, error) {
	// 先拷贝一份源文件
	nid := p.counter.Inc()

	srcBase := filepath.Join(p.workingDirectory, fmt.Sprintf("%s_%06d", p.file.name, nid))

	src := fmt.Sprintf("%s%s", srcBase, p.file.ext)
	err := copyTo(p.copyFilePath, src)
	if err != nil {
		return "", err
	}

	nfrf := fmt.Sprintf("%s.rf%s", srcBase, p.file.ext)
	nfp426 := fmt.Sprintf("%s.p426%s", srcBase, p.file.ext)
	nft := fmt.Sprintf("%s.adjust-time%s", srcBase, p.file.ext)
	nfm := fmt.Sprintf("%s.modify-ip%s", srcBase, p.file.ext)

	if p.file.finder.modifier.TsharkReadFilter != "" {
		pcapType := "pcap"
		if p.info.IsPcapNG() {
			pcapType = "pcapng"
		}
		result := pcapTool.tsharkReadFilter(src, nfrf, p.file.finder.modifier.TsharkReadFilter, pcapType, 0)
		if !result.succeed {
			return "", result.err
		}
		err := os.Rename(nfrf, src)
		if err != nil {
			return "", err
		}
	}

	if p.file.finder.modifier.P426 {
		err := ConvertPCAP(src, nfp426, p.info.IsPcapNG())
		if err != nil {
			return "", err
		}
		err = os.Rename(nfp426, src)
		if err != nil {
			return "", err
		}
	}

	if p.file.finder.modifier.ShufflePayload > 0 || p.file.finder.modifier.shufflePacket {
		err := shufflePCAP(src, nfp426, p.info.IsPcapNG(), ShuffleOptions{
			KeepN: p.file.finder.modifier.ShufflePayload,
			RandomPacket: p.file.finder.modifier.shufflePacket,
			RandomPacketN: p.file.finder.modifier.shufflePacketN,
			RandomPacketM: p.file.finder.modifier.shufflePacketM,
		})
		if err != nil {
			return "", err
		}
		err = os.Rename(nfp426, src)
		if err != nil {
			return "", err
		}
	}

	if p.file.finder.modifier.AdjustTime {
		result := pcapTool.adjustTime(src, nft, p.timeOffset())
		if !result.succeed {
			return "", result.err
		}
		err := os.Rename(nft, src)
		if err != nil {
			return "", err
		}
	}

	if !p.file.finder.modifier.KeepIp {

		hasIPv6 := p.hasIPv6 || p.file.finder.modifier.P426
		endpoints := p.file.finder.modifier.randomEndPoints(hasIPv6)
		result := pcapTool.modifyIp(src, nfm, p.cacheFilePath, endpoints, 0)
		if !result.succeed {
			return "", errors.New(fmt.Sprintf("can not modify ip: %s", result.err))
		}
		err := os.Rename(nfm, src)
		if err != nil {
			return "", err
		}
	}

	return src, nil
}

func parsePcapInfo(src string) (*PcapInfo, error) {
	result := pcapTool.getPcapInfo(src, 0)
	if result.succeed {
		v := viper.New()
		lines := strings.Split(result.output, "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			v.SetDefault(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
		info := &PcapInfo{}
		err := v.Unmarshal(info)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("error when parse capinfos output: %s", err))
		}
		err = info.parse()
		if err != nil {
			return info, err
		}
		return info, nil
	} else if result.output != "" {
		return nil, errors.New(result.output)
	} else {
		return nil, result.err
	}
}

func (p *Pcap) showWhy(why string) {
	if config.ShowWhyNotLoadPcap {
		logger.Warnln(fmt.Sprintf("%s %s", p, why))
	}
}
