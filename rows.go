// gcache-inspector - decode and summarize a Galera write-set cache (galera.cache).
//
// Copyright (C) 2026 Przemysław Malkowski
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

// rows.go implements decoding of binlog ROW events into mysqlbinlog
// "--base64-output=DECODE-ROWS -v" style output:
//
//   ### INSERT INTO `db`.`tbl`
//   ### SET
//   ###   @1=1
//   ###   @2='apple'
//   ###   @3=NULL
//
// Column names are not in the binlog (unless binlog_row_metadata=FULL), so
// columns are shown positionally as @1, @2, ... exactly like mysqlbinlog.
//
// The value formats were validated against the worked examples in the MySQL
// manual (the apple/pear INSERT/UPDATE/DELETE vectors) and the MariaDB KB
// row-event page (NEWDECIMAL, DATETIME2/TIMESTAMP2/TIME2 packed encodings).

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// MySQL column type codes (MYSQL_TYPE_*).
const (
	mDecimal    = 0
	mTiny       = 1
	mShort      = 2
	mLong       = 3
	mFloat      = 4
	mDouble     = 5
	mNull       = 6
	mTimestamp  = 7
	mLongLong   = 8
	mInt24      = 9
	mDate       = 10
	mTime       = 11
	mDatetime   = 12
	mYear       = 13
	mNewDate    = 14
	mVarchar    = 15
	mBit        = 16
	mTimestamp2 = 17
	mDatetime2  = 18
	mTime2      = 19
	mJSON       = 245
	mNewDecimal = 246
	mEnum       = 247
	mSet        = 248
	mTinyBlob   = 249
	mMedBlob    = 250
	mLongBlob   = 251
	mBlob       = 252
	mVarString  = 253
	mString     = 254
	mGeometry   = 255
)

var dig2bytes = []int{0, 1, 1, 2, 2, 3, 3, 4, 4, 4}

type tableDef struct {
	name  string
	ncols int
	types []byte
	metas []uint16
}

// packedInt reads a MySQL length-encoded integer.
func packedInt(d []byte, p int) (uint64, int, bool) {
	if p < 0 || p >= len(d) {
		return 0, p, false
	}
	n := d[p]
	switch {
	case n < 0xfb:
		return uint64(n), p + 1, true
	case n == 0xfc:
		if p+3 > len(d) {
			return 0, p, false
		}
		return uint64(binary.LittleEndian.Uint16(d[p+1 : p+3])), p + 3, true
	case n == 0xfd:
		if p+4 > len(d) {
			return 0, p, false
		}
		return uint64(d[p+1]) | uint64(d[p+2])<<8 | uint64(d[p+3])<<16, p + 4, true
	case n == 0xfe:
		if p+9 > len(d) {
			return 0, p, false
		}
		return binary.LittleEndian.Uint64(d[p+1 : p+9]), p + 9, true
	}
	return 0, p, false
}

// parseTableMapFull parses a TABLE_MAP event into a full table definition
// (name + per-column type and metadata), needed to decode row values.
func parseTableMapFull(data []byte, p, size int) (*tableDef, bool) {
	name, ok := parseTableMap(data, p, size)
	if !ok {
		return nil, false
	}
	o := p + headerLen + 8
	end := p + size
	// re-skip db and table names to reach the column section
	if o >= end {
		return nil, false
	}
	dbLen := int(data[o])
	o += 1 + dbLen + 1
	if o >= end {
		return nil, false
	}
	tblLen := int(data[o])
	o += 1 + tblLen + 1
	if o > end {
		return nil, false
	}
	ncols64, o, ok := packedInt(data, o)
	if !ok {
		return nil, false
	}
	ncols := int(ncols64)
	if ncols <= 0 || ncols > 4096 || o+ncols > end {
		return nil, false
	}
	types := make([]byte, ncols)
	copy(types, data[o:o+ncols])
	o += ncols
	mlen64, o, ok := packedInt(data, o)
	if !ok {
		return nil, false
	}
	mlen := int(mlen64)
	if o+mlen > end {
		return nil, false
	}
	metas, ok := decodeMeta(types, data[o:o+mlen])
	if !ok {
		return nil, false
	}
	return &tableDef{name: name, ncols: ncols, types: types, metas: metas}, true
}

// decodeMeta walks the TABLE_MAP metadata block, which stores a variable number
// of bytes per column depending on its type.
func decodeMeta(types []byte, md []byte) ([]uint16, bool) {
	metas := make([]uint16, len(types))
	pos := 0
	need := func(n int) bool { return pos+n <= len(md) }
	for i, t := range types {
		switch t {
		case mString, mNewDecimal, mEnum, mSet:
			if !need(2) {
				return nil, false
			}
			metas[i] = uint16(md[pos])<<8 | uint16(md[pos+1])
			pos += 2
		case mVarchar, mVarString, mBit:
			if !need(2) {
				return nil, false
			}
			metas[i] = uint16(md[pos]) | uint16(md[pos+1])<<8
			pos += 2
		case mBlob, mTinyBlob, mMedBlob, mLongBlob, mDouble, mFloat, mJSON,
			mGeometry, mTime2, mDatetime2, mTimestamp2:
			if !need(1) {
				return nil, false
			}
			metas[i] = uint16(md[pos])
			pos++
		default:
			metas[i] = 0
		}
	}
	return metas, true
}

func beUint(d []byte, p, n int) (uint64, bool) {
	if p+n > len(d) {
		return 0, false
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = (v << 8) | uint64(d[p+i])
	}
	return v, true
}

// decodeValue decodes a single non-NULL column value, returning the formatted
// string (quoted where mysqlbinlog would quote), the number of bytes consumed,
// and ok=false on any bounds problem so callers can stop cleanly.
func decodeValue(d []byte, p int, t byte, meta uint16) (string, int, bool) {
	switch t {
	case mTiny:
		if p+1 > len(d) {
			return "", 0, false
		}
		return strconv.FormatInt(int64(int8(d[p])), 10), 1, true
	case mShort:
		if p+2 > len(d) {
			return "", 0, false
		}
		return strconv.FormatInt(int64(int16(binary.LittleEndian.Uint16(d[p:]))), 10), 2, true
	case mInt24:
		if p+3 > len(d) {
			return "", 0, false
		}
		v := int32(d[p]) | int32(d[p+1])<<8 | int32(d[p+2])<<16
		if v&0x800000 != 0 {
			v -= 1 << 24
		}
		return strconv.FormatInt(int64(v), 10), 3, true
	case mLong:
		if p+4 > len(d) {
			return "", 0, false
		}
		return strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(d[p:]))), 10), 4, true
	case mLongLong:
		if p+8 > len(d) {
			return "", 0, false
		}
		return strconv.FormatInt(int64(binary.LittleEndian.Uint64(d[p:])), 10), 8, true
	case mFloat:
		if p+4 > len(d) {
			return "", 0, false
		}
		return strconv.FormatFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(d[p:]))), 'g', -1, 32), 4, true
	case mDouble:
		if p+8 > len(d) {
			return "", 0, false
		}
		return strconv.FormatFloat(math.Float64frombits(binary.LittleEndian.Uint64(d[p:])), 'g', -1, 64), 8, true
	case mYear:
		if p+1 > len(d) {
			return "", 0, false
		}
		if d[p] == 0 {
			return "0000", 1, true
		}
		return strconv.Itoa(int(d[p]) + 1900), 1, true
	case mNewDecimal:
		return decodeDecimal(d, p, int(meta>>8), int(meta&0xff))
	case mDate:
		if p+3 > len(d) {
			return "", 0, false
		}
		v := int(d[p]) | int(d[p+1])<<8 | int(d[p+2])<<16
		return fmt.Sprintf("'%04d-%02d-%02d'", v>>9, (v>>5)&15, v&31), 3, true
	case mTimestamp:
		if p+4 > len(d) {
			return "", 0, false
		}
		return fmt.Sprintf("'%d'", binary.LittleEndian.Uint32(d[p:])), 4, true
	case mDatetime:
		if p+8 > len(d) {
			return "", 0, false
		}
		v := binary.LittleEndian.Uint64(d[p:])
		sec := v % 100
		v /= 100
		mi := v % 100
		v /= 100
		h := v % 100
		v /= 100
		day := v % 100
		v /= 100
		mo := v % 100
		v /= 100
		return fmt.Sprintf("'%04d-%02d-%02d %02d:%02d:%02d'", v, mo, day, h, mi, sec), 8, true
	case mDatetime2:
		return decodeDatetime2(d, p, int(meta))
	case mTimestamp2:
		return decodeTimestamp2(d, p, int(meta))
	case mTime2:
		return decodeTime2(d, p, int(meta))
	case mVarchar, mVarString:
		return decodeString(d, p, int(meta))
	case mString:
		realType, length := unpackStringMeta(meta)
		if realType == mEnum || realType == mSet {
			n := 1
			if length > 0xff {
				n = 2
			}
			v, ok := readLE(d, p, n)
			if !ok {
				return "", 0, false
			}
			return strconv.FormatUint(v, 10), n, true
		}
		return decodeString(d, p, length)
	case mEnum:
		n := int(meta & 0xff)
		if n != 1 && n != 2 {
			n = 1
		}
		v, ok := readLE(d, p, n)
		if !ok {
			return "", 0, false
		}
		return strconv.FormatUint(v, 10), n, true
	case mSet:
		n := int(meta & 0xff)
		if n < 1 || n > 8 {
			n = 1
		}
		v, ok := readLE(d, p, n)
		if !ok {
			return "", 0, false
		}
		return strconv.FormatUint(v, 10), n, true
	case mBit:
		nbits := int(meta>>8)*8 + int(meta&0xff)
		nb := (nbits + 7) / 8
		v, ok := beUint(d, p, nb)
		if !ok {
			return "", 0, false
		}
		return strconv.FormatUint(v, 10), nb, true
	case mBlob, mTinyBlob, mMedBlob, mLongBlob:
		lb := int(meta)
		if lb < 1 || lb > 4 {
			return "", 0, false
		}
		ln, ok := readLE(d, p, lb)
		if !ok || p+lb+int(ln) > len(d) {
			return "", 0, false
		}
		return quoteBytes(d[p+lb : p+lb+int(ln)]), lb + int(ln), true
	case mJSON:
		lb := int(meta)
		ln, ok := readLE(d, p, lb)
		if !ok || p+lb+int(ln) > len(d) {
			return "", 0, false
		}
		return fmt.Sprintf("<JSON %d bytes>", ln), lb + int(ln), true
	case mGeometry:
		lb := int(meta)
		ln, ok := readLE(d, p, lb)
		if !ok || p+lb+int(ln) > len(d) {
			return "", 0, false
		}
		return fmt.Sprintf("<GEOMETRY %d bytes>", ln), lb + int(ln), true
	}
	return "", 0, false
}

func readLE(d []byte, p, n int) (uint64, bool) {
	if p+n > len(d) {
		return 0, false
	}
	var v uint64
	for i := 0; i < n; i++ {
		v |= uint64(d[p+i]) << (8 * i)
	}
	return v, true
}

func decodeString(d []byte, p, fieldLen int) (string, int, bool) {
	hl := 1
	if fieldLen > 0xff {
		hl = 2
	}
	ln, ok := readLE(d, p, hl)
	if !ok || p+hl+int(ln) > len(d) {
		return "", 0, false
	}
	return quoteBytes(d[p+hl : p+hl+int(ln)]), hl + int(ln), true
}

// unpackStringMeta decodes the quirky 2-byte STRING metadata that also carries
// the real type (CHAR/ENUM/SET) and the field length.
func unpackStringMeta(meta uint16) (realType byte, length int) {
	b0 := byte(meta >> 8)
	b1 := byte(meta & 0xff)
	if b0 == 0 {
		return mString, int(b1)
	}
	if b0&0x30 != 0x30 {
		length = int(b1) + (((int(b0) & 0x30) ^ 0x30) << 4)
		return b0 | 0x30, length
	}
	return b0, int(b1)
}

func decodeDecimal(d []byte, p, precision, scale int) (string, int, bool) {
	if precision <= 0 || scale < 0 || scale > precision {
		return "", 0, false
	}
	intg := precision - scale
	intg0 := intg / 9
	frac0 := scale / 9
	intg0x := intg - intg0*9
	frac0x := scale - frac0*9
	total := intg0*4 + dig2bytes[intg0x] + frac0*4 + dig2bytes[frac0x]
	if total == 0 || p+total > len(d) {
		return "", 0, false
	}
	buf := make([]byte, total)
	copy(buf, d[p:p+total])
	positive := buf[0]&0x80 != 0
	var mask byte
	if !positive {
		mask = 0xff
	}
	buf[0] ^= 0x80
	if mask != 0 {
		for i := range buf {
			buf[i] ^= 0xff
		}
	}
	pos := 0
	be := func(n int) uint64 {
		var v uint64
		for i := 0; i < n; i++ {
			v = (v << 8) | uint64(buf[pos+i])
		}
		pos += n
		return v
	}
	var istr strings.Builder
	if intg0x > 0 {
		fmt.Fprintf(&istr, "%d", be(dig2bytes[intg0x]))
	}
	for i := 0; i < intg0; i++ {
		v := be(4)
		if istr.Len() == 0 {
			fmt.Fprintf(&istr, "%d", v)
		} else {
			fmt.Fprintf(&istr, "%09d", v)
		}
	}
	intPart := strings.TrimLeft(istr.String(), "0")
	if intPart == "" {
		intPart = "0"
	}
	var fstr strings.Builder
	for i := 0; i < frac0; i++ {
		fmt.Fprintf(&fstr, "%09d", be(4))
	}
	if frac0x > 0 {
		fmt.Fprintf(&fstr, "%0*d", frac0x, be(dig2bytes[frac0x]))
	}
	sign := ""
	if !positive {
		sign = "-"
	}
	out := sign + intPart
	if scale > 0 {
		out += "." + fstr.String()
	}
	return out, total, true
}

func fracMicros(d []byte, p, decimals int) (string, int, bool) {
	nb := (decimals + 1) / 2
	if nb == 0 {
		return "", 0, true
	}
	v, ok := beUint(d, p, nb)
	if !ok {
		return "", 0, false
	}
	return fmt.Sprintf("%0*d", decimals, v), nb, true
}

func decodeDatetime2(d []byte, p, decimals int) (string, int, bool) {
	raw, ok := beUint(d, p, 5)
	if !ok {
		return "", 0, false
	}
	v := int64(raw) - 0x8000000000
	dpart := v >> 17
	tpart := v & ((1 << 17) - 1)
	day := dpart & 0x1f
	month := (dpart >> 5) % 13
	year := (dpart >> 5) / 13
	sec := tpart & 0x3f
	minute := (tpart >> 6) & 0x3f
	hour := tpart >> 12
	s := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, sec)
	f, nb, ok := fracMicros(d, p+5, decimals)
	if !ok {
		return "", 0, false
	}
	if f != "" {
		s += "." + f
	}
	return "'" + s + "'", 5 + nb, true
}

func decodeTimestamp2(d []byte, p, decimals int) (string, int, bool) {
	sec, ok := beUint(d, p, 4)
	if !ok {
		return "", 0, false
	}
	// Stored in UTC; format in UTC (no timezone info is available offline).
	days := int64(sec) / 86400
	rem := int64(sec) % 86400
	y, mo, da := civilFromDays(days)
	h := rem / 3600
	mi := (rem % 3600) / 60
	se := rem % 60
	s := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", y, mo, da, h, mi, se)
	f, nb, ok := fracMicros(d, p+4, decimals)
	if !ok {
		return "", 0, false
	}
	if f != "" {
		s += "." + f
	}
	return "'" + s + "'", 4 + nb, true
}

// civilFromDays converts days-since-Unix-epoch to a civil (y,m,d) date.
// Algorithm from Howard Hinnant's date library (public domain).
func civilFromDays(z int64) (int64, int64, int64) {
	z += 719468
	era := z
	if z < 0 {
		era = z - 146096
	}
	era /= 146097
	doe := z - era*146097
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d := doy - (153*mp+2)/5 + 1
	var m int64
	if mp < 10 {
		m = mp + 3
	} else {
		m = mp - 9
	}
	if m <= 2 {
		y++
	}
	return y, m, d
}

func decodeTime2(d []byte, p, decimals int) (string, int, bool) {
	raw, ok := beUint(d, p, 3)
	if !ok {
		return "", 0, false
	}
	v := int64(raw) - 0x800000
	hour := (v >> 12) & 0x3ff
	minute := (v >> 6) & 0x3f
	sec := v & 0x3f
	s := fmt.Sprintf("%02d:%02d:%02d", hour, minute, sec)
	f, nb, ok := fracMicros(d, p+3, decimals)
	if !ok {
		return "", 0, false
	}
	if f != "" {
		s += "." + f
	}
	return "'" + s + "'", 3 + nb, true
}

func quoteBytes(b []byte) string {
	var sb strings.Builder
	sb.WriteByte('\'')
	for _, c := range b {
		switch {
		case c == '\'':
			sb.WriteString("\\'")
		case c == '\\':
			sb.WriteString("\\\\")
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, "\\x%02x", c)
		}
	}
	sb.WriteByte('\'')
	return sb.String()
}

func bitLE(bitmap []byte, i int) bool {
	idx := i / 8
	if idx >= len(bitmap) {
		return false
	}
	return bitmap[idx]>>(uint(i)%8)&1 == 1
}

func countPresent(bitmap []byte, ncols int) int {
	c := 0
	for i := 0; i < ncols; i++ {
		if bitLE(bitmap, i) {
			c++
		}
	}
	return c
}

// decodeRowsEvent decodes a WRITE/UPDATE/DELETE_ROWS event body and appends
// mysqlbinlog-style text to out. v2 indicates the v2 wire format (extra-data).
func decodeRowsEvent(d []byte, p, size int, et byte, td *tableDef, out *strings.Builder) {
	// Never let malformed/mis-anchored bytes crash the whole tool.
	defer func() { _ = recover() }()

	end := p + size
	o := p + headerLen + 8 // common header + table_id(6) + flags(2)
	isV2 := et == evWriteRowsV2 || et == evUpdateRowsV2 || et == evDeleteRowsV2
	if isV2 {
		if o+2 > end {
			return
		}
		extra := int(binary.LittleEndian.Uint16(d[o:]))
		o += extra // extra includes its own 2 length bytes
	}
	isUpdate := et == evUpdateRowsV1 || et == evUpdateRowsV2
	isDelete := et == evDeleteRowsV1 || et == evDeleteRowsV2

	ncols64, o, ok := packedInt(d, o)
	if !ok {
		return
	}
	ncols := int(ncols64)
	if ncols != td.ncols || ncols <= 0 || ncols > 4096 {
		return // table map / row column count mismatch -> bail safely
	}
	bmLen := (ncols + 7) / 8
	if o+bmLen > end {
		return
	}
	present1 := d[o : o+bmLen]
	o += bmLen
	var present2 []byte
	if isUpdate {
		if o+bmLen > end {
			return
		}
		present2 = d[o : o+bmLen]
		o += bmLen
	}

	verb := ins("INSERT INTO")
	if isUpdate {
		verb = upd("UPDATE")
	} else if isDelete {
		verb = del("DELETE FROM")
	}
	qname := id(backquote(td.name))

	readImage := func(pos int, present []byte) ([]string, int, bool) {
		npres := countPresent(present, ncols)
		nnb := (npres + 7) / 8
		if pos+nnb > end {
			return nil, pos, false
		}
		nullmap := d[pos : pos+nnb]
		pos += nnb
		out := make([]string, ncols)
		ni := 0
		for c := 0; c < ncols; c++ {
			if !bitLE(present, c) {
				out[c] = ""
				continue
			}
			isNull := bitLE(nullmap, ni)
			ni++
			if isNull {
				out[c] = "NULL"
				continue
			}
			s, n, ok := decodeValue(d, pos, td.types[c], td.metas[c])
			if !ok {
				return nil, pos, false
			}
			out[c] = s
			pos += n
		}
		return out, pos, true
	}

	for o < end-4 || o < end { // stop near the optional 4-byte CRC trailer
		before, np, ok := readImage(o, present1)
		if !ok {
			return
		}
		o = np
		if isUpdate {
			after, np2, ok := readImage(o, present2)
			if !ok {
				return
			}
			o = np2
			fmt.Fprintf(out, "%s %s %s\n%s %s\n",
				dim("###"), verb, qname, dim("###"), dim("WHERE"))
			writeAssignments(out, before, present1, ncols)
			fmt.Fprintf(out, "%s %s\n", dim("###"), dim("SET"))
			writeAssignments(out, after, present2, ncols)
		} else {
			fmt.Fprintf(out, "%s %s %s\n", dim("###"), verb, qname)
			if isDelete {
				fmt.Fprintf(out, "%s %s\n", dim("###"), dim("WHERE"))
			} else {
				fmt.Fprintf(out, "%s %s\n", dim("###"), dim("SET"))
			}
			writeAssignments(out, before, present1, ncols)
		}
		if end-o <= 4 { // 0 = no checksum, 4 = CRC32 trailer
			break
		}
	}
}

// countRowsEvent returns the number of table rows touched by one row event:
// one row per image for INSERT/DELETE, one row per before+after pair for UPDATE.
// It walks the same row framing as decodeRowsEvent but skips value rendering.
// Returns 0 only if nothing could be parsed.
func countRowsEvent(d []byte, p, size int, et byte, td *tableDef) int {
	rows := 0
	defer func() { _ = recover() }()
	end := p + size
	o := p + headerLen + 8 // common header + table_id(6) + flags(2)
	if et == evWriteRowsV2 || et == evUpdateRowsV2 || et == evDeleteRowsV2 {
		if o+2 > end {
			return rows
		}
		o += int(binary.LittleEndian.Uint16(d[o:])) // extra-data (incl. length)
	}
	isUpdate := et == evUpdateRowsV1 || et == evUpdateRowsV2
	ncols64, o, ok := packedInt(d, o)
	if !ok {
		return rows
	}
	ncols := int(ncols64)
	if ncols != td.ncols || ncols <= 0 || ncols > 4096 {
		return rows
	}
	bmLen := (ncols + 7) / 8
	if o+bmLen > end {
		return rows
	}
	present1 := d[o : o+bmLen]
	o += bmLen
	var present2 []byte
	if isUpdate {
		if o+bmLen > end {
			return rows
		}
		present2 = d[o : o+bmLen]
		o += bmLen
	}
	skipImage := func(pos int, present []byte) (int, bool) {
		nnb := (countPresent(present, ncols) + 7) / 8
		if pos+nnb > end {
			return pos, false
		}
		nullmap := d[pos : pos+nnb]
		pos += nnb
		ni := 0
		for c := 0; c < ncols; c++ {
			if !bitLE(present, c) {
				continue
			}
			isNull := bitLE(nullmap, ni)
			ni++
			if isNull {
				continue
			}
			_, n, ok := decodeValue(d, pos, td.types[c], td.metas[c])
			if !ok {
				return pos, false
			}
			pos += n
		}
		return pos, true
	}
	for o < end {
		np, ok := skipImage(o, present1)
		if !ok {
			return rows
		}
		o = np
		if isUpdate {
			np2, ok := skipImage(o, present2)
			if !ok {
				return rows
			}
			o = np2
		}
		rows++
		if end-o <= 4 { // 0 = no checksum, 4 = CRC32 trailer
			break
		}
	}
	return rows
}

func writeAssignments(out *strings.Builder, vals []string, present []byte, ncols int) {
	for c := 0; c < ncols; c++ {
		if !bitLE(present, c) {
			continue
		}
		v := vals[c]
		if v == "NULL" {
			v = dim("NULL")
		}
		fmt.Fprintf(out, "%s %s\n",
			dim(fmt.Sprintf("###   @%d=", c+1)),
			v)
	}
}

func backquote(dbTable string) string {
	if i := strings.IndexByte(dbTable, '.'); i >= 0 {
		return "`" + dbTable[:i] + "`.`" + dbTable[i+1:] + "`"
	}
	return "`" + dbTable + "`"
}
