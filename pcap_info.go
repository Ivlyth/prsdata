package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (p *PcapInfo) parse() error {
	var err error
	vi, err := strconv.ParseInt(p.PacketCount, 10, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("errors when parse number of packets: %s", err))
	}
	p.packetCount = vi

	d, err := time.ParseDuration(strings.Replace(p.CaptureDuration, " seconds", "s", 1))
	if err != nil {
		return errors.New(fmt.Sprintf("errors when parse capture duration: %s", err))
	}
	p.captureDuration = d

	ts, err := strconv.ParseFloat(p.FirstPacketTime, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("errors when parse first packet time: %s", err))
	}
	p.firstPacketTime = time.Unix(int64(ts), 0)

	ts, err = strconv.ParseFloat(p.LastPacketTime, 64)
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
		return errors.New(fmt.Sprintf("errors when parse avg packet size: %s", err))
	}
	p.avgPacketSize = vf

	parts = strings.Split(p.AvgPacketRate, " ")
	if parts == nil || len(parts) == 0 {
		return errors.New("average packet rate is empty")
	}
	vf, err = strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return errors.New(fmt.Sprintf("errors when parse pps: %s", err))
	}
	p.avgPacketRate = vf

	return nil
}
