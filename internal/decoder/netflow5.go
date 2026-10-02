package decoder

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

const (
	nf5HeaderLen = 24
	nf5RecordLen = 48
)

func decodeNetFlow5(exporter netip.Addr, data []byte, now int64) (Result, error) {
	if len(data) < nf5HeaderLen {
		return Result{}, ErrShort
	}
	count := int(binary.BigEndian.Uint16(data[2:4]))
	if count == 0 || count > 30 {
		return Result{}, fmt.Errorf("netflow5: invalid record count %d", count)
	}
	if len(data) < nf5HeaderLen+count*nf5RecordLen {
		return Result{}, ErrShort
	}
	seq := binary.BigEndian.Uint32(data[16:20])
	engine := uint64(data[20])<<8 | uint64(data[21])
	// Upper 2 bits: sampling mode, lower 14 bits: interval.
	sampling := uint32(binary.BigEndian.Uint16(data[22:24]) & 0x3FFF)

	res := Result{
		Source:  flow.SourceNetFlow5,
		SeqKey:  engine,
		Seq:     seq,
		SeqNext: seq + uint32(count),
		Records: make([]flow.Record, 0, count),
	}
	for i := 0; i < count; i++ {
		b := data[nf5HeaderLen+i*nf5RecordLen : nf5HeaderLen+(i+1)*nf5RecordLen]
		first := binary.BigEndian.Uint32(b[24:28])
		last := binary.BigEndian.Uint32(b[28:32])
		r := flow.Record{
			ReceivedUnix: now,
			Exporter:     exporter,
			Source:       flow.SourceNetFlow5,
			SamplingRate: sampling,
			Src:          netip.AddrFrom4([4]byte(b[0:4])),
			Dst:          netip.AddrFrom4([4]byte(b[4:8])),
			InIf:         uint32(binary.BigEndian.Uint16(b[12:14])),
			OutIf:        uint32(binary.BigEndian.Uint16(b[14:16])),
			Packets:      uint64(binary.BigEndian.Uint32(b[16:20])),
			Bytes:        uint64(binary.BigEndian.Uint32(b[20:24])),
			SrcPort:      binary.BigEndian.Uint16(b[32:34]),
			DstPort:      binary.BigEndian.Uint16(b[34:36]),
			TCPFlags:     b[37],
			Protocol:     b[38],
			TOS:          b[39],
			SrcAS:        uint32(binary.BigEndian.Uint16(b[40:42])),
			DstAS:        uint32(binary.BigEndian.Uint16(b[42:44])),
		}
		if last >= first {
			r.DurationMs = clampDuration(uint64(last - first))
		}
		if r.Protocol == flow.ProtoICMP {
			r.ICMPType, r.ICMPCode = uint8(r.DstPort>>8), uint8(r.DstPort)
		}
		markPortlessFragment(&r)
		res.Records = append(res.Records, r)
	}
	return res, nil
}
