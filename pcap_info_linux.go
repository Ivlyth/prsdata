//+build !darwin

package main

import (
	"time"
)

type PcapInfo struct {
	Encapsulation   string `mapstructure:"file encapsulation"`
	PacketCount     string `mapstructure:"number of packets"`
	CaptureDuration string `mapstructure:"capture duration"`
	FirstPacketTime string `mapstructure:"start time"`
	LastPacketTime  string `mapstructure:"end time"`
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
