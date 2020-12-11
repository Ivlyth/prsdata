package main

import (
	"strconv"
	"strings"
	"time"
)

var (
	PCAP_INFO_ERR_PACKET_COUNT      int64 = 1
	PCAP_INFO_ERR_DURATION          int64 = 2
	PCAP_INFO_ERR_FIRST_PACKET_TIME int64 = 4
	PCAP_INFO_ERR_LAST_PACKET_TIME  int64 = 8
	PCAP_INFO_ERR_AVG_PACKET_SIZE   int64 = 16
	PCAP_INFO_ERR_AVG_PACKET_RATE   int64 = 32
)

type PcapInfo struct {
	Encapsulation   string `mapstructure:"file encapsulation"`
	PacketCount     string `mapstructure:"number of packets"`
	CaptureDuration string `mapstructure:"capture duration"`
	FirstPacketTime string `mapstructure:"first packet time"`
	LastPacketTime  string `mapstructure:"last packet time"`
	StartTime       string `mapstructure:"start time"`
	EndTime         string `mapstructure:"end time"`
	AvgPacketSize   string `mapstructure:"average packet size"`
	AvgPacketRate   string `mapstructure:"average packet rate"`
	SHA1            string `mapstructure:"sha1"`

	packetCount     int64
	captureDuration time.Duration
	firstPacketTime time.Time
	lastPacketTime  time.Time
	avgPacketSize   float64
	avgPacketRate   float64 // aka. pps

	error int64
}

func (p *PcapInfo) parse() error {
	var err error
	vi, err := strconv.ParseInt(p.PacketCount, 10, 64)
	if err != nil {
		p.packetCount = -1
		p.error |= PCAP_INFO_ERR_PACKET_COUNT
		//return errors.New(fmt.Sprintf("errors when parse number of packets: %s", err))
	} else {
		p.packetCount = vi
	}

	d, err := time.ParseDuration(strings.Replace(p.CaptureDuration, " seconds", "s", 1))
	if err != nil {
		p.error |= PCAP_INFO_ERR_DURATION
		//return errors.New(fmt.Sprintf("errors when parse capture duration: %s", err))
	} else {
		p.captureDuration = d
	}

	var firstPacketTime string
	if p.FirstPacketTime != "" {
		firstPacketTime = p.FirstPacketTime
	} else if p.StartTime != "" {
		firstPacketTime = p.StartTime
		p.FirstPacketTime = p.StartTime
	} else {
		p.error |= PCAP_INFO_ERR_FIRST_PACKET_TIME
		//return errors.New(fmt.Sprintf("no first packet time found"))
	}
	if firstPacketTime != "" {
		ts, err := strconv.ParseFloat(firstPacketTime, 64)
		if err != nil {
			p.error |= PCAP_INFO_ERR_FIRST_PACKET_TIME
			//return errors.New(fmt.Sprintf("errors when parse first packet time: %s", err))
		} else {
			p.firstPacketTime = time.Unix(int64(ts), 0)
		}
	}

	var lastPacketTime string
	if p.LastPacketTime != "" {
		lastPacketTime = p.LastPacketTime
	} else if p.EndTime != "" {
		lastPacketTime = p.EndTime
		p.LastPacketTime = p.EndTime
	} else {
		p.error |= PCAP_INFO_ERR_LAST_PACKET_TIME
		//return errors.New(fmt.Sprintf("no last packet time found"))
	}
	if lastPacketTime != "" {
		ts, err := strconv.ParseFloat(lastPacketTime, 64)
		if err != nil {
			p.error |= PCAP_INFO_ERR_LAST_PACKET_TIME
			//return errors.New(fmt.Sprintf("errors when parse last packet time: %s", err))
		} else {
			p.lastPacketTime = time.Unix(int64(ts), 0)
		}
	}

	parts := strings.Split(p.AvgPacketSize, " ")
	if parts == nil || len(parts) == 0 {
		p.avgPacketSize = -1
		p.error |= PCAP_INFO_ERR_AVG_PACKET_SIZE
		//return errors.New("average packet size is empty")
	} else {
		vf, err := strconv.ParseFloat(parts[0], 64)
		if err != nil {
			p.avgPacketSize = -1
			p.error |= PCAP_INFO_ERR_AVG_PACKET_SIZE
			//return errors.New(fmt.Sprintf("errors when parse avg packet size: %s", err))
		} else {
			p.avgPacketSize = vf
		}
	}

	parts = strings.Split(p.AvgPacketRate, " ")
	if parts == nil || len(parts) == 0 {
		p.avgPacketRate = -1
		p.error |= PCAP_INFO_ERR_AVG_PACKET_RATE
		//return errors.New("average packet rate is empty")
	} else {
		vf, err := strconv.ParseFloat(parts[0], 64)
		if err != nil {
			p.avgPacketRate = -1
			p.error |= PCAP_INFO_ERR_AVG_PACKET_RATE
			//return errors.New(fmt.Sprintf("errors when parse pps: %s", err))
		} else {
			p.avgPacketRate = vf
		}
	}

	return nil
}
