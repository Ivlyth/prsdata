package main

import (
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

var (
	modifiers       = make(map[string]*Modifier)
	defaultModifier = &Modifier{}
)

type Modifier struct {
	Id string `mapstructure:"id"`

	// 调整的时间偏移量, 单位: 秒
	AdjustTime bool          `mapstructure:"adjust_time"`
	TimeOffset time.Duration `mapstructure:"time_offset"`

	KeepIp   bool `mapstructure:"keep_ip"`
	C1       int  `mapstructure:"c1"`
	C2       int  `mapstructure:"c2"`
	C3       int  `mapstructure:"c3"`
	C4       int  `mapstructure:"c4"`
	S1       int  `mapstructure:"s1"`
	S2       int  `mapstructure:"s2"`
	S3       int  `mapstructure:"s3"`
	S4       int  `mapstructure:"s4"`
	UsePart3 bool `mapstructure:"use_part_3"`
	UsePart4 bool `mapstructure:"use_part_4"`

	// 尝试将 IPv4 转换为 IPv6
	P426 bool
	// 大于 0 表示开启 payload shuffle，保留指定数量的字节不打乱
	ShufflePayload int    `mapstructure:"shuffle_payload"`
	ShufflePacket  string `mapstructure:"shuffle_packet"`

	shufflePacket bool    // 是否开启 packet 顺序随机打乱功能
	shufflePacketN  int   // 保留前 n 个
	shufflePacketM  int   // 保留后 m 个

	TsharkReadFilter string `mapstructure:"tshark_filter"`

	Used bool // 是否被某个 job 的 command 使用到
}

func (m *Modifier) String() string {
	if m.Id != "" {
		return fmt.Sprintf("[Modifier-%s]", m.Id)
	} else {
		return "[Modifier]"
	}
}

func (m *Modifier) check() error {

	if err := checkId(m.Id); err != nil {
		return err
	}

	if _, ok := modifiers[m.Id]; ok {
		return errors.New(fmt.Sprintf("duplicate modifier id: %s", m.Id))
	}

	if m.C1 < 0 || m.C1 > 255 {
		return errors.New(fmt.Sprintf("invalid c1: %d", m.C1))
	}
	if m.C2 < 0 || m.C2 > 255 {
		return errors.New(fmt.Sprintf("invalid c2: %d", m.C2))
	}
	if m.C3 < 0 || m.C3 > 255 {
		return errors.New(fmt.Sprintf("invalid c3: %d", m.C3))
	}
	if m.C4 < 0 || m.C4 > 255 {
		return errors.New(fmt.Sprintf("invalid c4: %d", m.C4))
	}

	if m.S1 < 0 || m.S1 > 255 {
		return errors.New(fmt.Sprintf("invalid s1: %d", m.S1))
	}
	if m.S2 < 0 || m.S2 > 255 {
		return errors.New(fmt.Sprintf("invalid s2: %d", m.S2))
	}
	if m.S3 < 0 || m.S3 > 255 {
		return errors.New(fmt.Sprintf("invalid s3: %d", m.S3))
	}
	if m.S4 < 0 || m.S4 > 255 {
		return errors.New(fmt.Sprintf("invalid s4: %d", m.S4))
	}

	if m.ShufflePacket == "" || m.ShufflePacket == "false" {
		m.shufflePacket = false
	} else if m.ShufflePacket == "true" {
		m.shufflePacket = true
		m.shufflePacketN = 3
		m.shufflePacketM = 4
	} else {
		parts := strings.Split(m.ShufflePacket, ":")
		if len(parts) != 2 {
			return errors.New(fmt.Sprintf("invalid shuffle-packet format: %s", m.ShufflePacket))
		}
		N, err := strconv.Atoi(parts[0])
		if err != nil {
			return errors.New(fmt.Sprintf("invalid n for shuffle-packet: %s", parts[0]))
		}
		if N < 0 {
			return errors.New(fmt.Sprintf("invalid n for shuffle-packet: %d, must be larger than or equal to 0", N))
		}
		M, err := strconv.Atoi(parts[1])
		if err != nil {
			return errors.New(fmt.Sprintf("invalid m for shuffle-packet: %s", parts[1]))
		}
		if M < 0 {
			return errors.New(fmt.Sprintf("invalid m for shuffle-packet: %d, must be larger than or equal to 0", N))
		}
		m.shufflePacket = true
		m.shufflePacketN = N
		m.shufflePacketM = M
	}

	return nil
}

func (m *Modifier) randomEndPoints(hasIPv6 bool) string {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	c3 := r1.Int31n(255)
	s3 := r1.Int31n(255)

	c4 := r1.Int31n(255)
	s4 := r1.Int31n(255)

	c_mask := r1.Intn(5)
	s_mask := r1.Intn(5)

	if m.UsePart4 {
		c3 = int32(m.C3)
		s3 = int32(m.S3)

		c4 = int32(m.C4)
		s4 = int32(m.S4)

		c_mask = 32
		s_mask = 32
	} else if m.UsePart3 {
		c3 = int32(m.C3)
		s3 = int32(m.S3)

		c_mask += 24
		s_mask += 24
	} else { // use part2
		c_mask += 16
		s_mask += 16
	}

	if hasIPv6 {
		c_mask += 96
		s_mask += 96
		return fmt.Sprintf("[0100::ffff:%02x%02x:%02x%02x/%d]:[0100::ffff:%02x%02x:%02x%02x/%d]", m.C1, m.C2, c3, c4, c_mask, m.S1, m.S2, s3, s4, s_mask)
	} else {
		return fmt.Sprintf("%d.%d.%d.%d/%d:%d.%d.%d.%d/%d", m.C1, m.C2, c3, c4, c_mask, m.S1, m.S2, s3, s4, s_mask)
	}
}
