package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	logger "github.com/sirupsen/logrus"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

type pcapWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
}

type ShuffleOptions struct {
	KeepN         int
	RandomPacket  bool
	RandomPacketN int
	RandomPacketM int
}

func shufflePCAP(oldFilename, newFilename string, usePcapNg bool, options ShuffleOptions) error {
	oldFile, err := os.Open(oldFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file %s not exist", oldFilename)
		} else {
			return fmt.Errorf("cannot open file %s: %w", oldFilename, err)
		}
	}
	defer oldFile.Close()

	newFile, err := os.OpenFile(newFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		return fmt.Errorf("cannot create (and truncate) file %s: %w", newFilename, err)
	}

	defer newFile.Close()

	ext := filepath.Ext(oldFilename)

	newExt := filepath.Ext(newFilename)

	if ext != newExt {
		return fmt.Errorf("the extension of old file %s must be equal to the new file %s", oldFilename, newFilename)
	}

	return shufflePacketByReader(oldFile, newFile, usePcapNg, options)
}

func shufflePacketByReader(oldFileReader io.Reader, newFileWriter io.Writer, usePcapNg bool, options ShuffleOptions) error {
	var oldFileSource *gopacket.PacketSource
	var linkType layers.LinkType

	if usePcapNg {
		source, err := pcapgo.NewNgReader(oldFileReader, pcapgo.DefaultNgReaderOptions)

		if err != nil {
			return fmt.Errorf("cannot build pcapng reader: %w", err)
		}

		linkType = source.LinkType()
		oldFileSource = gopacket.NewPacketSource(source, linkType)
	} else {
		source, err := pcapgo.NewReader(oldFileReader)

		if err != nil {
			return fmt.Errorf("cannot build pcap reader: %w", err)
		}

		linkType = source.LinkType()
		oldFileSource = gopacket.NewPacketSource(source, linkType)
	}

	var newPcapWriter pcapWriter

	if usePcapNg {
		writer, err := pcapgo.NewNgWriter(newFileWriter, linkType)

		if err != nil {
			return fmt.Errorf("cannot build pcapng writer: %w", err)
		}

		defer writer.Flush()

		newPcapWriter = writer
	} else {
		writer := pcapgo.NewWriter(newFileWriter)

		err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet)

		if err != nil {
			return fmt.Errorf("cannot build pcap writer (error when write file header): %w", err)
		}

		newPcapWriter = writer
	}

	return shufflePacketAndWrite(oldFileSource, newPcapWriter, options)
}

func shufflePacketAndWrite(oldPacketSource *gopacket.PacketSource, newFileWriter pcapWriter, options ShuffleOptions) error {
	packets := make([]gopacket.Packet, 0, 10)

	for packet := range oldPacketSource.Packets() {
		packets = append(packets, packet)
	}

	// 保留 前n 后m 然后对中间部分进行打乱
	// 如果 小于等于 n+m+1 个 packet, 不进行操作
	if options.RandomPacket && len(packets) > (options.RandomPacketN+options.RandomPacketM+1) {
		tmpPackets := packets[options.RandomPacketN : len(packets)-options.RandomPacketM]

		s1 := rand.NewSource(time.Now().UnixNano())
		r1 := rand.New(s1)

		r1.Shuffle(len(tmpPackets), func(i, j int) {
			tmpPackets[i], tmpPackets[j] = tmpPackets[j], tmpPackets[i]
		})
	}

	newPackets := make([][]byte, 0, len(packets))

	shuffledCount := 0

	for i, packet := range packets {
		var b []byte
		var err error

		if options.KeepN > 0 {
			b, err = shufflePacketPayload(packet, options.KeepN)

			if err != nil {
				logger.Debugf("Cannot shuffle packet [%d], not modify. (%s)\n", i, err)

				b, err = serializePacket(packet)

				if err != nil {
					return fmt.Errorf("invalid packet [%d] (cannot serialize): %w", i, err)
				}
			} else {
				shuffledCount++
			}
		} else {
			b, err = serializePacket(packet)

			if err != nil {
				return fmt.Errorf("invalid packet [%d] (cannot serialize): %w", i, err)
			}
		}

		newPackets = append(newPackets, b)
	}

	if options.KeepN > 0 && shuffledCount == 0 {
		return fmt.Errorf("can not shuffle any packet")
	}

	for i := 0; i < len(newPackets); i++ {
		newPacket := newPackets[i]
		oldPacketInfo := packets[i].Metadata().CaptureInfo

		err := newFileWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:      oldPacketInfo.Timestamp,
			CaptureLength:  len(newPacket),
			Length:         len(newPacket),
			InterfaceIndex: oldPacketInfo.InterfaceIndex,
			AncillaryData:  oldPacketInfo.AncillaryData,
		}, newPacket)

		if err != nil {
			return fmt.Errorf("error when write modified packet [%d] to file: %w", i, err)
		}
	}

	return nil
}

func ConvertPCAP(oldFilename, newFilename string, usePcapNg bool) error {
	oldFile, err := os.Open(oldFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file %s not exist", oldFilename)
		} else {
			return fmt.Errorf("cannot open file %s: %w", oldFilename, err)
		}
	}
	defer oldFile.Close()

	newFile, err := os.OpenFile(newFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		return fmt.Errorf("cannot create (and truncate) file %s: %w", newFilename, err)
	}

	defer newFile.Close()

	ext := filepath.Ext(oldFilename)

	newExt := filepath.Ext(newFilename)

	if ext != newExt {
		return fmt.Errorf("the extension of old file %s must be equal to the new file %s", oldFilename, newFilename)
	}

	return ConvertPacketByReader(oldFile, newFile, usePcapNg)
}

func ConvertPacketByReader(oldFileReader io.Reader, newFileWriter io.Writer, usePcapNg bool) error {
	var oldFileSource *gopacket.PacketSource
	var linkType layers.LinkType

	if usePcapNg {
		source, err := pcapgo.NewNgReader(oldFileReader, pcapgo.DefaultNgReaderOptions)

		if err != nil {
			return fmt.Errorf("cannot build pcapng reader: %w", err)
		}

		linkType = source.LinkType()
		oldFileSource = gopacket.NewPacketSource(source, linkType)
	} else {
		source, err := pcapgo.NewReader(oldFileReader)

		if err != nil {
			return fmt.Errorf("cannot build pcap reader: %w", err)
		}

		linkType = source.LinkType()
		oldFileSource = gopacket.NewPacketSource(source, linkType)
	}

	var newPcapWriter pcapWriter

	if usePcapNg {
		writer, err := pcapgo.NewNgWriter(newFileWriter, linkType)

		if err != nil {
			return fmt.Errorf("cannot build pcapng writer: %w", err)
		}

		defer writer.Flush()

		newPcapWriter = writer
	} else {
		writer := pcapgo.NewWriter(newFileWriter)

		err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet)

		if err != nil {
			return fmt.Errorf("cannot build pcap writer (error when write file header): %w", err)
		}

		newPcapWriter = writer
	}

	return ConvertPacketAndWrite(oldFileSource, newPcapWriter)
}

func ConvertPacketAndWrite(oldPacketSource *gopacket.PacketSource, newFileWriter pcapWriter) error {
	packets := make([]gopacket.Packet, 0, 10)

	for packet := range oldPacketSource.Packets() {
		packets = append(packets, packet)
	}

	newPackets := make([][]byte, 0, len(packets))

	for i, packet := range packets {
		b, err := ConvertIPv4PacketToIPv6(packet)

		if err != nil {
			logger.Debugf("Cannot convert packet [%d], not modify. (%s)\n", i, err)

			b, err = serializePacket(packet)

			if err != nil {
				return fmt.Errorf("invalid packet [%d] (cannot serialize): %w", i, err)
			}

		}

		newPackets = append(newPackets, b)
	}

	// 写入前两层
	for i := 0; i < len(newPackets); i++ {
		newPacket := newPackets[i]
		oldPacketInfo := packets[i].Metadata().CaptureInfo

		err := newFileWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:      oldPacketInfo.Timestamp,
			CaptureLength:  len(newPacket),
			Length:         len(newPacket),
			InterfaceIndex: oldPacketInfo.InterfaceIndex,
			AncillaryData:  oldPacketInfo.AncillaryData,
		}, newPacket)

		if err != nil {
			return fmt.Errorf("error when write modified packet [%d] to file: %w", i, err)
		}
	}

	return nil
}

func serializePacket(packet gopacket.Packet) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}

	err := gopacket.SerializePacket(buf, options, packet)

	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func shufflePayload(payload []byte, keepN int) []byte {
	if keepN <= 0 || len(payload) <= keepN {
		return payload
	}

	buf := make([]byte, len(payload), len(payload))

	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	r1.Shuffle(len(payload)-keepN, func(i, j int) {
		payload[keepN+i], payload[keepN+j] = payload[keepN+j], payload[keepN+i]
	})

	copy(buf, payload)

	return buf
}

func shufflePacketPayload(packet gopacket.Packet, keepN int) ([]byte, error) {
	allLayers := packet.Layers()

	// 转换所有 layer 为可序列化对象
	serializableLayers := make([]gopacket.SerializableLayer, len(allLayers))

	// 原样转存 3 层及更高
	for i, layer := range allLayers {
		if l, ok := layer.(gopacket.SerializableLayer); ok {
			serializableLayers[i] = l
		} else {
			return nil, fmt.Errorf("%dth layer is not serializable (type is %s)", i, layer.LayerType())
		}
	}

	// 序列化 packet
	buf := gopacket.NewSerializeBuffer()

	doNothing := gopacket.SerializeOptions{}
	fixInfo := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	var sOpt gopacket.SerializeOptions

	for i := len(serializableLayers) - 1; i >= 0; i-- {
		layer := serializableLayers[i]

		if layer.LayerType() == gopacket.LayerTypePayload {
			payload := layer.(*gopacket.Payload).LayerContents()
			payload = shufflePayload(payload, keepN)
			*layer.(*gopacket.Payload) = payload
		}

		if layer.LayerType() == layers.LayerTypeEthernet || layer.LayerType() == layers.LayerTypeIPv4 || layer.LayerType() == layers.LayerTypeIPv6 {
			sOpt = fixInfo
		} else {
			sOpt = doNothing
		}

		err := layer.SerializeTo(buf, sOpt)
		if err != nil {
			return nil, fmt.Errorf("cannot serialize %dth layer: %w", i+1, err)
		}

		buf.PushLayer(layer.LayerType())
	}

	return buf.Bytes(), nil
}

func ConvertIPv4PacketToIPv6(packet gopacket.Packet) ([]byte, error) {
	allLayers := packet.Layers()

	// 一个标准的 packet 至少应当有 3 层：Ethernet、IP、TCP/UDP，对于不符合的直接忽略

	if len(allLayers) < 3 {
		return nil, fmt.Errorf("len(layers) < 3")
	}

	// 第一层必须是以太网层
	l0 := allLayers[0]
	if l0.LayerType() != layers.LayerTypeEthernet {
		return nil, fmt.Errorf("first layer is %s (not Ethernet)", l0.LayerType())
	}

	// 第二层必须是 IP 层
	l1 := allLayers[1]
	if l1.LayerType() != layers.LayerTypeIPv4 {
		return nil, fmt.Errorf("second layer is %s (not IPv4)", l1.LayerType())
	}

	// 第三层必须是 TCP / UDP 层
	l2 := allLayers[2]
	isTCP := false
	if l2.LayerType() == layers.LayerTypeTCP {
		isTCP = true
	} else if l2.LayerType() != layers.LayerTypeUDP {
		return nil, fmt.Errorf("third layer is %s (not TCP/UDP)", l2.LayerType())
	}

	// 转换所有 layer 为可序列化对象
	serializableLayers := make([]gopacket.SerializableLayer, len(allLayers))

	// 原样转存 3 层及更高
	for i := 2; i < len(allLayers); i++ {
		if l, ok := allLayers[i].(gopacket.SerializableLayer); ok {
			serializableLayers[i] = l
		} else {
			return nil, fmt.Errorf("%dth layer is not serializable (type is %s)", i, allLayers[i].LayerType())
		}
	}

	// 转换 Ethernet 层
	ethLayer := l0.(*layers.Ethernet)
	ethLayer.EthernetType = layers.EthernetTypeIPv6
	serializableLayers[0] = ethLayer

	// 转换 IP 层
	ipv4Layer := l1.(*layers.IPv4)
	srcIP := ipv4Layer.SrcIP.To16()
	srcIP[0] = 0x01
	dstIP := ipv4Layer.DstIP.To16()
	dstIP[0] = 0x01
	ipv6Layer := &layers.IPv6{
		Version: 6,
		SrcIP:   srcIP,
		DstIP:   dstIP,
	}
	if isTCP {
		ipv6Layer.NextHeader = layers.IPProtocolTCP
	} else {
		ipv6Layer.NextHeader = layers.IPProtocolUDP
	}

	serializableLayers[1] = ipv6Layer

	// 序列化 packet

	buf := gopacket.NewSerializeBuffer()

	doNothing := gopacket.SerializeOptions{}
	fixInfo := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// 序列化（三层及以后）
	for i := len(serializableLayers) - 1; i >= 2; i-- {
		layer := serializableLayers[i]

		err := layer.SerializeTo(buf, doNothing)
		if err != nil {
			return nil, fmt.Errorf("cannot serialize %dth layer: %w", i+1, err)
		}

		buf.PushLayer(layer.LayerType())
	}

	// 序列化二层
	err := serializableLayers[1].SerializeTo(buf, fixInfo)
	if err != nil {
		return nil, fmt.Errorf("cannot serialize second layer: %w", err)
	}

	// 序列化一层
	err = serializableLayers[0].SerializeTo(buf, fixInfo)
	if err != nil {
		return nil, fmt.Errorf("cannot serialize first layer: %w", err)
	}

	return buf.Bytes(), nil
}
