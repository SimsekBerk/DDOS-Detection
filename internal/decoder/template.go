package decoder

import (
	"encoding/binary"
	"net/netip"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

const (
	nf9HeaderLen   = 20
	ipfixHeaderLen = 16
	varLen         = 0xFFFF
)

func (d *Decoder) decodeNetFlow9(exporter netip.Addr, data []byte, now int64) (Result, error) {
	if len(data) < nf9HeaderLen {
		return Result{}, ErrShort
	}
	seq := binary.BigEndian.Uint32(data[12:16])
	domain := binary.BigEndian.Uint32(data[16:20])
	res := Result{Source: flow.SourceNetFlow9, SeqKey: uint64(domain), Seq: seq, SeqNext: seq + 1}

	off := nf9HeaderLen
	for off+4 <= len(data) {
		setID := binary.BigEndian.Uint16(data[off : off+2])
		setLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(data) {
			break // malformed or truncated flowset; keep what we have
		}
		body := data[off+4 : off+setLen]
		switch {
		case setID == 0:
			res.TemplatesLearned += d.parseNF9Templates(exporter, domain, body)
		case setID == 1:
			res.TemplatesLearned += d.parseNF9OptionsTemplates(exporter, domain, body)
		case setID >= 256:
			d.decodeDataSet(&res, exporter, domain, setID, body, false, now, flow.SourceNetFlow9)
		}
		off += setLen
	}
	return res, nil
}

func (d *Decoder) parseNF9Templates(exporter netip.Addr, domain uint32, b []byte) int {
	n := 0
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b[0:2])
		count := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]
		if id < 256 || len(b) < count*4 {
			break
		}
		t := &template{fields: make([]fieldSpec, count)}
		for i := 0; i < count; i++ {
			t.fields[i] = fieldSpec{id: binary.BigEndian.Uint16(b[i*4:]), length: binary.BigEndian.Uint16(b[i*4+2:])}
		}
		b = b[count*4:]
		d.mu.Lock()
		d.nf9[tmplKey{exporter, domain, id}] = t
		d.mu.Unlock()
		n++
	}
	return n
}

func (d *Decoder) parseNF9OptionsTemplates(exporter netip.Addr, domain uint32, b []byte) int {
	n := 0
	for len(b) >= 6 {
		id := binary.BigEndian.Uint16(b[0:2])
		scopeLen := int(binary.BigEndian.Uint16(b[2:4]))
		optLen := int(binary.BigEndian.Uint16(b[4:6]))
		b = b[6:]
		if id < 256 || scopeLen%4 != 0 || optLen%4 != 0 || len(b) < scopeLen+optLen {
			break
		}
		t := &template{options: true, scopeCount: scopeLen / 4}
		for i := 0; i < (scopeLen+optLen)/4; i++ {
			t.fields = append(t.fields, fieldSpec{id: binary.BigEndian.Uint16(b[i*4:]), length: binary.BigEndian.Uint16(b[i*4+2:])})
		}
		b = b[scopeLen+optLen:]
		d.mu.Lock()
		d.nf9[tmplKey{exporter, domain, id}] = t
		d.mu.Unlock()
		n++
	}
	return n
}

func (d *Decoder) decodeIPFIX(exporter netip.Addr, data []byte, now int64) (Result, error) {
	if len(data) < ipfixHeaderLen {
		return Result{}, ErrShort
	}
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	if msgLen < ipfixHeaderLen || msgLen > len(data) {
		return Result{}, ErrShort
	}
	data = data[:msgLen]
	seq := binary.BigEndian.Uint32(data[8:12])
	domain := binary.BigEndian.Uint32(data[12:16])
	res := Result{Source: flow.SourceIPFIX, SeqKey: uint64(domain), Seq: seq}

	off := ipfixHeaderLen
	dataRecords := 0
	for off+4 <= len(data) {
		setID := binary.BigEndian.Uint16(data[off : off+2])
		setLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(data) {
			break
		}
		body := data[off+4 : off+setLen]
		switch {
		case setID == 2:
			res.TemplatesLearned += d.parseIPFIXTemplates(exporter, domain, body, false)
		case setID == 3:
			res.TemplatesLearned += d.parseIPFIXTemplates(exporter, domain, body, true)
		case setID >= 256:
			before := len(res.Records) + res.OptionRecords
			d.decodeDataSet(&res, exporter, domain, setID, body, true, now, flow.SourceIPFIX)
			dataRecords += len(res.Records) + res.OptionRecords - before
		}
		off += setLen
	}
	res.SeqNext = seq + uint32(dataRecords)
	return res, nil
}

func (d *Decoder) parseIPFIXTemplates(exporter netip.Addr, domain uint32, b []byte, options bool) int {
	n := 0
	hdr := 4
	if options {
		hdr = 6
	}
	for len(b) >= hdr {
		id := binary.BigEndian.Uint16(b[0:2])
		count := int(binary.BigEndian.Uint16(b[2:4]))
		scope := 0
		if options {
			scope = int(binary.BigEndian.Uint16(b[4:6]))
		}
		b = b[hdr:]
		if id < 256 {
			break // padding or invalid
		}
		key := tmplKey{exporter, domain, id}
		if count == 0 { // template withdrawal
			d.mu.Lock()
			delete(d.ipfix, key)
			d.mu.Unlock()
			continue
		}
		t := &template{options: options, scopeCount: scope}
		ok := true
		for i := 0; i < count; i++ {
			if len(b) < 4 {
				ok = false
				break
			}
			fs := fieldSpec{id: binary.BigEndian.Uint16(b[0:2]), length: binary.BigEndian.Uint16(b[2:4])}
			b = b[4:]
			if fs.id&0x8000 != 0 {
				if len(b) < 4 {
					ok = false
					break
				}
				fs.id &= 0x7FFF
				fs.enterprise = binary.BigEndian.Uint32(b[0:4])
				b = b[4:]
			}
			t.fields = append(t.fields, fs)
		}
		if !ok {
			break
		}
		d.mu.Lock()
		d.ipfix[key] = t
		d.mu.Unlock()
		n++
	}
	return n
}

// decodeDataSet walks the records of one data set using its template.
func (d *Decoder) decodeDataSet(res *Result, exporter netip.Addr, domain uint32, setID uint16, b []byte, ipfix bool, now int64, src flow.Source) {
	key := tmplKey{exporter, domain, setID}
	d.mu.Lock()
	var t *template
	if ipfix {
		t = d.ipfix[key]
	} else {
		t = d.nf9[key]
	}
	learned := d.sampling[samplingKey{exporter, domain}]
	d.mu.Unlock()
	if t == nil {
		res.MissingTemplate++
		return
	}

	minLen := 0
	for _, f := range t.fields {
		if f.length == varLen {
			minLen++
		} else {
			minLen += int(f.length)
		}
	}
	if minLen == 0 {
		return
	}

	for len(b) >= minLen {
		var r flow.Record
		var st recordState
		ok := true
		for _, f := range t.fields {
			l := int(f.length)
			if f.length == varLen {
				if len(b) < 1 {
					ok = false
					break
				}
				l = int(b[0])
				b = b[1:]
				if l == 255 {
					if len(b) < 2 {
						ok = false
						break
					}
					l = int(binary.BigEndian.Uint16(b[0:2]))
					b = b[2:]
				}
			}
			if len(b) < l {
				ok = false
				break
			}
			if f.enterprise == 0 {
				applyField(&r, &st, f.id, b[:l])
			}
			b = b[l:]
		}
		if !ok {
			break
		}
		if t.options {
			res.OptionRecords++
			if rate := samplingFromState(&st); rate > 0 {
				d.mu.Lock()
				d.sampling[samplingKey{exporter, domain}] = rate
				d.mu.Unlock()
				learned = rate
			}
			continue
		}
		finish(&r, &st)
		if !r.Src.IsValid() || !r.Dst.IsValid() {
			continue // e.g. L2-only or MPLS-only records
		}
		r.ReceivedUnix = now
		r.Exporter = exporter
		r.Source = src
		r.SamplingRate = samplingFromState(&st)
		if r.SamplingRate == 0 {
			r.SamplingRate = learned
		}
		res.Records = append(res.Records, r)
	}
}
