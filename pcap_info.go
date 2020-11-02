package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
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
}

func (p *PcapInfo) parse() error {
	var err error
	vi, err := strconv.ParseInt(p.PacketCount, 10, 64)
	if err != nil {
		p.packetCount = -1
		return errors.New(fmt.Sprintf("errors when parse number of packets: %s", err))
	}
	p.packetCount = vi

	d, err := time.ParseDuration(strings.Replace(p.CaptureDuration, " seconds", "s", 1))
	if err != nil {
		return errors.New(fmt.Sprintf("errors when parse capture duration: %s", err))
	}
	p.captureDuration = d

	var firstPacketTime string
	if p.FirstPacketTime != "" {
		firstPacketTime = p.FirstPacketTime
	} else if p.StartTime != "" {
		firstPacketTime = p.StartTime
	} else {
		return errors.New(fmt.Sprintf("no first packet time found"))
	}
	ts, err := strconv.ParseFloat(firstPacketTime, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("errors when parse first packet time: %s", err))
	}
	p.firstPacketTime = time.Unix(int64(ts), 0)

	var lastPacketTime string
	if p.LastPacketTime != "" {
		lastPacketTime = p.LastPacketTime
	} else if p.EndTime != "" {
		lastPacketTime = p.EndTime
	} else {
		return errors.New(fmt.Sprintf("no last packet time found"))
	}
	ts, err = strconv.ParseFloat(lastPacketTime, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("errors when parse last packet time: %s", err))
	}
	p.lastPacketTime = time.Unix(int64(ts), 0)

	parts := strings.Split(p.AvgPacketSize, " ")
	if parts == nil || len(parts) == 0 {
		return errors.New("average packet size is empty")
	}
	vf, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		p.avgPacketSize = -1
		return errors.New(fmt.Sprintf("errors when parse avg packet size: %s", err))
	}
	p.avgPacketSize = vf

	parts = strings.Split(p.AvgPacketRate, " ")
	if parts == nil || len(parts) == 0 {
		return errors.New("average packet rate is empty")
	}
	vf, err = strconv.ParseFloat(parts[0], 64)
	if err != nil {
		p.avgPacketRate = -1
		return errors.New(fmt.Sprintf("errors when parse pps: %s", err))
	}
	p.avgPacketRate = vf

	return nil
}
