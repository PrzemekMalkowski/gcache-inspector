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

// gcache-inspector decodes a Galera write-set cache (galera.cache) and summarizes
// its contents the way mysqlbinlog summarizes a binary log: which tables were
// touched, and how often, broken down by insert/update/delete.
//
// Background on the on-disk format (PXC 8.0/8.4 and MariaDB Galera both use the
// codership/galera provider, so the layout is shared):
//
//   1. PREAMBLE  - a plain-text header at the start of the file. The provider
//      writes it in gcache/src/gcache_rb_store.cpp (write_preamble/open_preamble).
//      Real lines look like:
//          Version: 2
//          UUID: b9c73149-5739-11f0-bc6e-47ff7b5cdcda
//          Seqno: 1 - 1109
//          Offset: 4096
//          Synced: 1
//
//   2. RING BUFFER - after the preamble, write-sets are stored back-to-back in a
//      circular buffer, each prefixed by a binary BufferHeader (gcache/src/
//      gcache_bh.hpp). The exact BufferHeader layout is version-specific and is
//      not relied on here (it embeds live mmap pointers that are meaningless once
//      the file is read offline, which is why gcache.recover has to "repossess"
//      them on startup).
//
//   3. WRITE-SET PAYLOAD - the data part of each write-set is, for a row-based
//      cluster, a binlog image of the rows changed by the transaction
//      (see Percona's "Understanding GCache and Record-Set Cache"). In other
//      words the table identity and operation type live inside ordinary binlog
//      ROW events, exactly like in a .000001 binlog file.
//
// Rather than chase the version-specific BufferHeader/WriteSetNG framing, this
// tool scans the whole file for embedded binlog TABLE_MAP_EVENTs (type 19) and
// the WRITE/UPDATE/DELETE_ROWS events that reference them. TABLE_MAP carries the
// database+table name; row events carry only a numeric table_id, so we keep a
// running table_id -> name map as we walk each contiguous binlog run (= one
// write-set's payload). This approach is robust across PXC/MySQL (v2 row events,
// type 30/31/32) and MariaDB (v1 row events, type 23/24/25, plus ANNOTATE_ROWS).
//
// Binlog layout used below (all integers little-endian):
//   common header (19 bytes): timestamp[4] type[1] server_id[4] event_size[4]
//                             log_pos[4] flags[2]
//   TABLE_MAP post-header (8): table_id[6] flags[2]
//   TABLE_MAP body:           db_len[1] db[db_len] 0x00 tbl_len[1] tbl[tbl_len] 0x00 ...
//   ROWS post-header:         table_id[6] flags[2] [v2: extra_len[2] extra...]
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Binlog event type codes.
const (
	evQuery        = 0x02
	evXID          = 0x10
	evTableMap     = 0x13 // 19
	evWriteRowsV1  = 0x17 // 23  (MariaDB / pre-5.6)
	evUpdateRowsV1 = 0x18 // 24
	evDeleteRowsV1 = 0x19 // 25
	evWriteRowsV2  = 0x1e // 30  (MySQL 5.6+/8.0, PXC)
	evUpdateRowsV2 = 0x1f // 31
	evDeleteRowsV2 = 0x20 // 32
	evGTIDLog      = 0x21 // 33  (MySQL GTID_LOG_EVENT)
	evAnnotateRows = 0xa0 // 160 (MariaDB)
	evMariaGTID    = 0xa2 // 162 (MariaDB GTID_EVENT)
	// MariaDB compressed row events (best-effort).
	evWriteRowsCompV1  = 0xa5 // 165
	evUpdateRowsCompV1 = 0xa6 // 166
	evDeleteRowsCompV1 = 0xa7 // 167
)

const headerLen = 19 // binlog common header length

// rowOp maps a row-event type code to a logical operation.
var rowOp = map[byte]string{
	evWriteRowsV1: "insert", evUpdateRowsV1: "update", evDeleteRowsV1: "delete",
	evWriteRowsV2: "insert", evUpdateRowsV2: "update", evDeleteRowsV2: "delete",
	evWriteRowsCompV1: "insert", evUpdateRowsCompV1: "update", evDeleteRowsCompV1: "delete",
}

// knownEvent is the set of event types that may legitimately appear inside a
// write-set's binlog stream. The walker uses it to step over GTID/Query/Xid/
// Annotate events between row events without derailing.
var knownEvent = map[byte]bool{
	evQuery: true, evXID: true, evTableMap: true,
	evWriteRowsV1: true, evUpdateRowsV1: true, evDeleteRowsV1: true,
	evWriteRowsV2: true, evUpdateRowsV2: true, evDeleteRowsV2: true,
	evGTIDLog: true, evAnnotateRows: true, evMariaGTID: true,
	evWriteRowsCompV1: true, evUpdateRowsCompV1: true, evDeleteRowsCompV1: true,
	0x04: true, // ROTATE
	0x1b: true, // HEARTBEAT / RAND etc. (tolerated)
}

type tableStats struct {
	Inserts uint64
	Updates uint64
	Deletes uint64
	DDLs    uint64
	Bytes   uint64
}

func (t *tableStats) ops() uint64    { return t.Inserts + t.Updates + t.Deletes }
func (t *tableStats) events() uint64 { return t.Inserts + t.Updates + t.Deletes + t.DDLs }

// runRec describes one contiguous binlog run = one write-set's payload.
type runRec struct {
	start, end int
	bufSize    int    // full gcache buffer size from the framing header (live only)
	flags      uint32 // gcache BufferHeader flags (RELEASED/SKIPPED), when readable
	hasFlags   bool
	ddl        int
	ddlText    []string
	tables     map[string]*tableStats
	seqno      int64 // Galera global seqno, or -1 if not attributable (stale)
	live       bool
}

// gcache BufferHeader flag bits (gcache_bh.hpp).
const (
	bhReleased = 1 << 0 // buffer no longer pinned by any consumer
	bhSkipped  = 1 << 1 // buffer skipped (e.g. dummy / not replicated)
)

func flagString(r *runRec) string {
	if !r.hasFlags {
		return ""
	}
	var parts []string
	if r.flags&bhReleased != 0 {
		parts = append(parts, "RELEASED")
	}
	if r.flags&bhSkipped != 0 {
		parts = append(parts, "SKIPPED")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "|")
}

func (r *runRec) bytes() int { return r.end - r.start }

type summary struct {
	FileName  string
	TotalSize uint64
	Version   uint32
	UUID      string
	SeqnoMin  int64
	SeqnoMax  int64
	HasSeqno  bool
	Offset    int64
	Synced    string

	// Encryption (crypt.go): preamble metadata plus what we managed to do
	// with it.
	Enc          encInfo
	Decrypted    bool
	EncScheme    string
	EncKeySource string
	EncNote      string
	EncEmptyRB   bool // decrypted fine, but the ring buffer holds no write-sets

	Runs        int   // contiguous binlog runs found (~ write-sets w/ row/DDL data)
	RangeKnown  bool  // preamble carried a valid retained seqno range
	SeqnoChecked bool // whether per-run seqno attribution was performed
	Attributed  int   // runs we could assign a seqno to (from headers)
	DerivedMin  int64 // min/max seqno derived from headers (when range unknown)
	DerivedMax  int64
	LiveWS      int   // runs within the retained seqno range (RangeKnown only)
	StaleWS     int   // runs outside it (older / overwritten leftovers)
	DDLCount    int   // DDL statements found
	SizeOff     int   // auto-detected BufferHeader size-field offset (diagnostics)
	CandCount   int   // header seqno candidates found (diagnostics)
	GTIDs       int   // GTID events seen (~ transactions)
	RowsChanged uint64  // total modified rows (not binlog events)
	RowBytes    uint64
	EventHist   map[byte]uint64
	Tables      map[string]*tableStats
	RunList     []*runRec
	data        []byte
	SawV2, SawV1, SawMaria bool
}

const (
	appName = "gcache-inspector"
	version = "0.2.0"
)

var (
	filePath     = flag.String("file", "", "Path to galera.cache file")
	summaryOnly  = flag.Bool("summary-only", false, "Show only the header summary, skip the table breakdown")
	topN         = flag.Int("top", 10, "Number of top tables to show")
	detail       = flag.Bool("detail", false, "List each write-set: seqno, size, flags, table ops, DDL count")
	debug        = flag.Bool("debug", false, "Show event-type histogram and header auto-calibration diagnostics")
	decodeRows   = flag.Bool("decode-rows", false, "Decode each row event into mysqlbinlog DECODE-ROWS -v style output")
	limit        = flag.Int("limit", 0, "When decoding, max number of write-sets to print (0 = all)")
	includeStale = flag.Bool("include-stale", false, "Also include stale write-sets (leftovers from earlier ring-buffer cycles)")
	liveOnly     = flag.Bool("live-only", false, "Restrict table/row aggregates to retained write-sets (in the seqno range)")
	showVersion  = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Parse()
	initColor()
	if *showVersion {
		fmt.Printf("%s %s\n", appName, version)
		return
	}
	if *filePath == "" {
		fmt.Printf("%s %s\n", appName, version)
		fmt.Printf("Usage: %s --file /path/to/galera.cache [--summary-only] [--top 20]\n", appName)
		fmt.Println("       [--detail] [--decode-rows [--limit 50]] [--include-stale] [--live-only] [--debug]")
		fmt.Println("Encrypted caches:")
		fmt.Println("       [--keyring-file /path/component_keyring_file | --master-key HEX |")
		fmt.Println("        --vault-url URL --vault-token TOKEN [--vault-mount m] [--vault-path p]]")
		fmt.Println("       [--dump-preamble] [--enc-probe] [--file-key HEX]")
		fmt.Println("       [--enc-scheme S --enc-page-size N --enc-base OFF]")
		os.Exit(1)
	}

	if *dumpPreamble {
		if err := dumpPreambleText(*filePath); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *encProbe {
		data, err := os.ReadFile(*filePath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		printProbe(*filePath, data, probe(data))
		return
	}

	sum, err := parseGCache(*filePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	printSummary(sum, *topN)
	if *detail {
		printDetail(sum)
	}
	if *decodeRows {
		printDecode(sum)
	}
}

func parseGCache(path string) (*summary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := &summary{
		FileName:  path,
		TotalSize: uint64(len(data)),
		Tables:    make(map[string]*tableStats),
		EventHist: make(map[byte]uint64),
	}

	// 1. Preamble (first few KB is plain text).
	parsePreamble(data, sum)
	sum.RangeKnown = sum.HasSeqno && sum.SeqnoMin > 0 && sum.SeqnoMax >= sum.SeqnoMin

	// 2. If the cache is encrypted, decrypt the ring buffer in memory. On
	//    failure this returns the original bytes and records why on the
	//    summary, so the header info is still printed.
	data = maybeDecrypt(data, sum)

	// 3. Deep-scan the whole file for binlog write-set payloads.
	scan(data, sum)

	// 4. Attribute Galera seqnos only when per-write-set output is requested -
	//    the header scan isn't needed for the plain summary, so we skip it there
	//    to keep that path fast.
	if *detail || *decodeRows || *debug {
		attributeSeqnos(data, sum)
		sum.SeqnoChecked = true
	}

	// 5. Roll up per-run stats into the summary totals.
	aggregate(sum)

	// Keep the decode pass able to re-read the bytes.
	sum.data = data
	return sum, nil
}

func parsePreamble(data []byte, s *summary) {
	n := 4096
	if len(data) < n {
		n = len(data)
	}
	for _, raw := range strings.Split(string(data[:n]), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.IndexByte(line, ':') < 0 {
			continue
		}
		key := strings.TrimSpace(line[:strings.IndexByte(line, ':')])
		val := strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
		s.Enc.note(key, val) // encryption keys differ per build; see crypt.go
		switch strings.ToLower(key) {
		case "version":
			fmt.Sscanf(val, "%d", &s.Version)
		case "uuid", "gid":
			s.UUID = firstToken(val)
		case "seqno":
			// "min - max"
			var a, b int64
			if _, e := fmt.Sscanf(val, "%d - %d", &a, &b); e == nil {
				s.SeqnoMin, s.SeqnoMax, s.HasSeqno = a, b, true
			}
		case "seqno_min":
			fmt.Sscanf(val, "%d", &s.SeqnoMin)
			s.HasSeqno = true
		case "seqno_max":
			fmt.Sscanf(val, "%d", &s.SeqnoMax)
			s.HasSeqno = true
		case "offset":
			fmt.Sscanf(val, "%d", &s.Offset)
		case "synced":
			s.Synced = firstToken(val)
		}
	}
}

func firstToken(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// readEvent returns (type, size) for a candidate binlog event at p, or ok=false
// if the bytes can't be a well-formed event within the file.
func readEvent(data []byte, p int) (byte, int, bool) {
	if p < 0 || p+13 > len(data) {
		return 0, 0, false
	}
	ttype := data[p+4]
	size := int(binary.LittleEndian.Uint32(data[p+9 : p+13]))
	if size < headerLen || p+size > len(data) {
		return 0, 0, false
	}
	return ttype, size, true
}

// tableID reads the 6-byte little-endian table_id that begins the post-header of
// both TABLE_MAP and ROWS events (offset p+19).
func tableID(data []byte, p int) uint64 {
	o := p + headerLen
	if o+6 > len(data) {
		return ^uint64(0)
	}
	return uint64(data[o]) | uint64(data[o+1])<<8 | uint64(data[o+2])<<16 |
		uint64(data[o+3])<<24 | uint64(data[o+4])<<32 | uint64(data[o+5])<<40
}

// parseTableMap extracts db.table from a TABLE_MAP event, validating that the
// names are real identifiers terminated by NUL. Returns ok=false on any mismatch,
// which lets the scanner reject false-positive anchors found in binary junk.
func parseTableMap(data []byte, p, size int) (string, bool) {
	o := p + headerLen + 8 // skip common header + 8-byte TABLE_MAP post-header
	end := p + size
	if o >= end || o >= len(data) {
		return "", false
	}
	dbLen := int(data[o])
	o++
	if dbLen < 1 || dbLen > 64 || o+dbLen+1 > end {
		return "", false
	}
	db := data[o : o+dbLen]
	o += dbLen
	if data[o] != 0x00 { // NUL terminator
		return "", false
	}
	o++
	if o >= end {
		return "", false
	}
	tblLen := int(data[o])
	o++
	if tblLen < 1 || tblLen > 64 || o+tblLen+1 > end {
		return "", false
	}
	tbl := data[o : o+tblLen]
	o += tblLen
	if data[o] != 0x00 {
		return "", false
	}
	if !identOK(db) || !identOK(tbl) {
		return "", false
	}
	return string(db) + "." + string(tbl), true
}

// identOK reports whether b looks like a MySQL identifier (the unquoted subset,
// which covers virtually all real table/schema names in replication).
func identOK(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '$':
		default:
			return false
		}
	}
	return true
}

// scan walks the whole file, collecting each contiguous binlog run (= one
// write-set payload) into s.RunList. A run is anchored either on a valid
// TABLE_MAP (DML) or on a DDL QUERY event (DDL-only write-sets have no
// TABLE_MAP). Seqno attribution and aggregation happen afterwards.
func scan(data []byte, s *summary) {
	p := 0
	n := len(data)
	for p < n-headerLen {
		ttype, size, ok := readEvent(data, p)
		anchor := false
		if ok {
			if ttype == evTableMap {
				if _, mok := parseTableMap(data, p, size); mok {
					anchor = true
				}
			} else if ttype == evQuery {
				if isDDL(queryKeyword(data, p, size)) {
					anchor = true
				}
			}
		}
		if !anchor {
			p++
			continue
		}

		s.Runs++
		rec := &runRec{start: p, seqno: -1, tables: map[string]*tableStats{}}
		cur := map[uint64]*tableDef{}
		rp := p
	runLoop:
		for rp < n-headerLen {
			et, esz, eok := readEvent(data, rp)
			if !eok || !knownEvent[et] {
				break
			}
			s.EventHist[et]++
			switch {
			case et == evGTIDLog || et == evMariaGTID:
				s.GTIDs++
				if et == evMariaGTID {
					s.SawMaria = true
				}
			case et == evAnnotateRows:
				s.SawMaria = true
			case et == evQuery:
				if isDDL(queryKeyword(data, rp, esz)) {
					schema, txt := queryText(data, rp, esz)
					rec.ddl++
					rec.ddlText = append(rec.ddlText, txt)
					if tbl := extractDDLTable(txt, schema); tbl != "" {
						st := rec.tables[tbl]
						if st == nil {
							st = &tableStats{}
							rec.tables[tbl] = st
						}
						st.DDLs++
					}
				}
			case et == evTableMap:
				td, mok := parseTableMapFull(data, rp, esz)
				if !mok {
					rp += esz
					break runLoop
				}
				cur[tableID(data, rp)] = td
			default:
				if op, isRow := rowOp[et]; isRow {
					switch et {
					case evWriteRowsV2, evUpdateRowsV2, evDeleteRowsV2:
						s.SawV2 = true
					case evWriteRowsV1, evUpdateRowsV1, evDeleteRowsV1:
						s.SawV1 = true
					}
					td := cur[tableID(data, rp)]
					name := "(unknown table)"
					rows := 1
					if td != nil {
						name = td.name
						if r := countRowsEvent(data, rp, esz, et, td); r > 0 {
							rows = r
						}
					}
					addRow(rec.tables, name, op, uint64(esz), rows)
				}
			}
			rp += esz
		}
		rec.end = rp
		s.RunList = append(s.RunList, rec)
		if rp <= p {
			rp = p + 1
		}
		p = rp
	}
}

var ddlKeywords = map[string]bool{
	"CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true, "RENAME": true,
}

func isDDL(kw string) bool { return ddlKeywords[kw] }

// queryBodyStart returns the offset where a QUERY_EVENT's SQL text begins, the
// event end, and the schema (current database). ok=false if the header is bad.
func queryBodyStart(d []byte, p, size int) (qo, end int, schema string, ok bool) {
	o := p + headerLen
	end = p + size
	if o+13 > end || o+13 > len(d) {
		return 0, 0, "", false
	}
	schemaLen := int(d[o+8])
	statusLen := int(binary.LittleEndian.Uint16(d[o+11 : o+13]))
	so := o + 13 + statusLen
	if so >= 0 && so+schemaLen <= end && so+schemaLen <= len(d) {
		schema = string(d[so : so+schemaLen])
	}
	qo = so + schemaLen + 1
	if qo < 0 || qo > end || end > len(d) {
		return 0, 0, schema, false
	}
	return qo, end, schema, true
}

// queryKeyword cheaply returns just the leading SQL keyword (upper-cased),
// reading at most a couple dozen bytes. This is what the whole-file scan uses to
// test for DDL, so a false-positive QUERY event with a huge size field costs
// nothing (the old code materialized the entire claimed query as a string,
// which on a 128 MB file added up to tens of GB of copying).
func queryKeyword(d []byte, p, size int) string {
	qo, end, _, ok := queryBodyStart(d, p, size)
	if !ok {
		return ""
	}
	for qo < end && (d[qo] == ' ' || d[qo] == '\t' || d[qo] == '\n' || d[qo] == '\r') {
		qo++
	}
	lim := qo + 24
	if lim > end {
		lim = end
	}
	i := qo
	for i < lim && d[i] > ' ' && d[i] != '(' {
		i++
	}
	if i == qo {
		return ""
	}
	return strings.ToUpper(string(d[qo:i]))
}

// queryText returns the schema and (capped) statement text. Only called once a
// DDL keyword is confirmed, so the cap also guards against pathological sizes.
func queryText(d []byte, p, size int) (schema, txt string) {
	qo, end, schema, ok := queryBodyStart(d, p, size)
	if !ok {
		return schema, ""
	}
	if end-qo > 8192 {
		end = qo + 8192
	}
	q := d[qo:end]
	for n := 0; len(q) > 0 && n < 8 && (q[len(q)-1] < 0x20 || q[len(q)-1] >= 0x7f); n++ {
		q = q[:len(q)-1]
	}
	return schema, strings.TrimSpace(string(q))
}

// extractDDLTable best-effort finds the table a DDL statement targets, so DDL
// can be attributed to a table in the activity ranking. Handles the common
// CREATE/ALTER/DROP/TRUNCATE/RENAME TABLE and CREATE INDEX ... ON forms.
func extractDDLTable(sql, schema string) string {
	toks := strings.Fields(sql)
	for i, t := range toks {
		u := strings.ToUpper(t)
		if u != "TABLE" && u != "ON" {
			continue
		}
		j := i + 1
		for j < len(toks) {
			switch strings.ToUpper(toks[j]) {
			case "IF", "NOT", "EXISTS":
				j++
				continue
			}
			break
		}
		if j < len(toks) {
			return qualifyTable(toks[j], schema)
		}
	}
	return ""
}

func qualifyTable(tok, schema string) string {
	tok = strings.Trim(tok, "(),;`")
	tok = strings.ReplaceAll(tok, "`", "")
	if k := strings.IndexAny(tok, "(,;"); k >= 0 {
		tok = tok[:k]
	}
	if tok == "" {
		return ""
	}
	if strings.Contains(tok, ".") {
		return tok
	}
	if schema != "" {
		return schema + "." + tok
	}
	return tok
}

// gcache BufferHeader (gcache_bh.hpp, packed, 24 bytes):
//   seqno_g int64  @+0   (-1 == SEQNO_ILL once the buffer is purged/discarded)
//   ctx     uint64 @+8   (in-memory pointer; meaningless on disk)
//   size    uint32 @+16  (total buffer size incl. header; next header = H+size)
//   flags   uint16 @+20  (BUFFER_RELEASED=1, BUFFER_SKIPPED=2)
//   store   int8   @+22  (BUFFER_IN_RB == 1)
//   type    int8   @+23
const (
	bhSize    = 24
	bhInRB    = 1 // StorageType BUFFER_IN_RB
	bhFlagMax = 3 // BUFFER_FLAGS_MAX = (SKIPPED<<1)-1
	seqnoIll  = -1
)

// attributeSeqnos finds each write-set's BufferHeader using the authoritative
// gcache layout and reads its seqno. A live buffer carries its real seqno in
// seqno_g (@+0). A purged/released buffer has seqno_g == -1 (discard() resets
// it), and the only surviving copy of the seqno is inside the write-set payload;
// for those we recover it from a payload offset calibrated against the buffers
// that still have a valid seqno_g (or, failing that, by plausibility).
func attributeSeqnos(data []byte, s *summary) {
	if len(s.RunList) == 0 {
		return
	}
	s.RangeKnown = s.HasSeqno && s.SeqnoMin > 0 && s.SeqnoMax >= s.SeqnoMin
	lo, hi := s.SeqnoMin, s.SeqnoMax
	n := len(data)

	// 1. Locate BufferHeaders by the BH_test signature (store==BUFFER_IN_RB,
	//    flags<=MAX, size frames). The store byte is the cheap first filter.
	type bhdr struct {
		H, size int
		flags   uint16
		seqno   int64
	}
	var bhs []bhdr
	for H := 0; H+bhSize <= n; H++ {
		if data[H+22] != bhInRB {
			continue
		}
		if data[H+23] > 4 { // type: user-defined but small in practice
			continue
		}
		flags := binary.LittleEndian.Uint16(data[H+20 : H+22])
		if flags > bhFlagMax {
			continue
		}
		size := int(binary.LittleEndian.Uint32(data[H+16 : H+20]))
		if size < bhSize || H+size > n {
			continue
		}
		seqno := int64(binary.LittleEndian.Uint64(data[H : H+8]))
		if seqno < seqnoIll {
			continue
		}
		bhs = append(bhs, bhdr{H, size, flags, seqno})
	}
	s.CandCount = len(bhs)
	if len(bhs) == 0 {
		return
	}
	s.SizeOff = 16 // fixed by the struct; kept for the debug line

	starts := make([]int, len(bhs))
	for i := range bhs {
		starts[i] = bhs[i].H
	}

	// Confirm headers by ring-buffer chaining: real buffers tile contiguously, so
	// a real header's H+size lands exactly on the next header. A signature that
	// coincidentally matches inside a keyset won't chain, so this drops the false
	// positives that would otherwise shadow the real (often far-away) header.
	linked := make([]bool, len(bhs))
	anyLink := false
	for i := range bhs {
		j := sort.SearchInts(starts, bhs[i].H+bhs[i].size)
		if j < len(starts) && starts[j] == bhs[i].H+bhs[i].size {
			linked[i], linked[j], anyLink = true, true, true
		}
	}
	if anyLink {
		kept := bhs[:0]
		for i := range bhs {
			if linked[i] {
				kept = append(kept, bhs[i])
			}
		}
		bhs = kept
		starts = starts[:0]
		for i := range bhs {
			starts = append(starts, bhs[i].H)
		}
		s.CandCount = len(bhs)
	}

	// 2. Map each run to the buffer whose payload contains it.
	hdrOf := make([]int, len(s.RunList)) // index into bhs, or -1
	for i, r := range s.RunList {
		hdrOf[i] = -1
		k := sort.Search(len(starts), func(j int) bool { return starts[j] > r.start }) - 1
		for c := k; c >= 0 && c > k-16; c-- {
			b := bhs[c]
			if b.H+bhSize <= r.start && r.start < b.H+b.size {
				hdrOf[i] = c
				break
			}
		}
	}

	// 3. Calibrate the payload seqno offset for purged buffers (seqno_g == -1),
	//    using runs whose buffer still has a valid seqno_g as ground truth.
	payOff := -1
	{
		type known struct {
			H     int
			seqno int64
		}
		var live []known
		for i := range s.RunList {
			if hdrOf[i] < 0 {
				continue
			}
			b := bhs[hdrOf[i]]
			if b.seqno > 0 {
				live = append(live, known{b.H, b.seqno})
			}
		}
		if len(live) > 0 {
			for _, off := range []int{0, 8, 16, 24, 32, 40} {
				ok, hit := true, 0
				for _, lk := range live {
					p := lk.H + bhSize + off
					if p+8 > n {
						ok = false
						break
					}
					if int64(binary.LittleEndian.Uint64(data[p:p+8])) == lk.seqno {
						hit++
					}
				}
				if ok && hit == len(live) {
					payOff = off
					break
				}
			}
		} else {
			// No ground truth: choose the offset whose values are positive,
			// within the seqno bound, and monotonic across runs in file order.
			bound := int64(1) << 48
			if s.RangeKnown {
				bound = hi
			}
			best := -1
			for _, off := range []int{8, 0, 16, 24, 32, 40} {
				var prev int64 = -1 << 62
				inb, mono, cnt := 0, true, 0
				for i := range s.RunList {
					if hdrOf[i] < 0 {
						continue
					}
					p := bhs[hdrOf[i]].H + bhSize + off
					if p+8 > n {
						continue
					}
					v := int64(binary.LittleEndian.Uint64(data[p : p+8]))
					cnt++
					if v >= 1 && v <= bound {
						inb++
					}
					if v < prev {
						mono = false
					}
					prev = v
				}
				score := inb
				if mono {
					score += 1000
				}
				if cnt > 0 && score > best {
					best, payOff = score, off
				}
			}
		}
	}

	// 4. Assign seqno (header if live, else payload), size, flags.
	var dmin, dmax int64 = 1 << 62, -1
	for i, r := range s.RunList {
		if hdrOf[i] < 0 {
			continue
		}
		b := bhs[hdrOf[i]]
		r.bufSize = b.size
		r.flags = uint32(b.flags)
		r.hasFlags = true
		seqno := b.seqno
		if seqno <= 0 && payOff >= 0 {
			p := b.H + bhSize + payOff
			if p+8 <= n {
				if v := int64(binary.LittleEndian.Uint64(data[p : p+8])); v > 0 {
					seqno = v
				}
			}
		}
		if seqno <= 0 {
			continue
		}
		r.seqno = seqno
		s.Attributed++
		if seqno < dmin {
			dmin = seqno
		}
		if seqno > dmax {
			dmax = seqno
		}
		if s.RangeKnown {
			r.live = seqno >= lo && seqno <= hi
		} else {
			r.live = true
		}
	}
	if s.Attributed > 0 {
		s.DerivedMin, s.DerivedMax = dmin, dmax
	}
}

// aggregate rolls per-run stats into the summary totals. When seqno attribution
// wasn't performed (plain summary), every run is included and no live/stale split
// is computed. With attribution, --live-only restricts to retained write-sets.
func aggregate(s *summary) {
	s.Tables = map[string]*tableStats{}
	for _, r := range s.RunList {
		if s.SeqnoChecked {
			if r.live {
				s.LiveWS++
			} else {
				s.StaleWS++
			}
			if *liveOnly && !r.live {
				continue
			}
		}
		s.DDLCount += r.ddl
		for name, t := range r.tables {
			g := s.Tables[name]
			if g == nil {
				g = &tableStats{}
				s.Tables[name] = g
			}
			g.Inserts += t.Inserts
			g.Updates += t.Updates
			g.Deletes += t.Deletes
			g.DDLs += t.DDLs
			g.Bytes += t.Bytes
			s.RowsChanged += t.ops()
			s.RowBytes += t.Bytes
		}
	}
}

// decodeRun re-walks a single run and renders its row events (and any DDL) in
// mysqlbinlog DECODE-ROWS -v style.
func decodeRun(data []byte, r *runRec) string {
	var out strings.Builder
	cur := map[uint64]*tableDef{}
	rp := r.start
	for rp < r.end {
		et, esz, ok := readEvent(data, rp)
		if !ok || !knownEvent[et] {
			break
		}
		switch {
		case et == evTableMap:
			if td, dok := parseTableMapFull(data, rp, esz); dok {
				cur[tableID(data, rp)] = td
			}
		case et == evQuery:
			if isDDL(queryKeyword(data, rp, esz)) {
				_, txt := queryText(data, rp, esz)
				fmt.Fprintf(&out, "%s %s\n", dim("###"), ddlColor(txt))
			}
		default:
			if _, isRow := rowOp[et]; isRow {
				if td := cur[tableID(data, rp)]; td != nil {
					decodeRowsEvent(data, rp, esz, et, td, &out)
				}
			}
		}
		rp += esz
	}
	return out.String()
}

// selectedRuns returns runs to print. With a known retained range we show the
// retained write-sets (plus stale if --include-stale). Without a range (live
// node) we show every write-set, since we can't tell which are retained.
func selectedRuns(s *summary) []*runRec {
	seqKey := func(r *runRec) int64 {
		if r.seqno > 0 {
			return r.seqno
		}
		return int64(1) << 62 // unattributed sort last
	}
	// Show all runs (labeled by seqno) when attribution found nothing, or when
	// no run falls in the retained range - e.g. the retained write-sets carry no
	// row data and the decodable ones are all just-older (seen on PXC 8.4.8).
	if !s.RangeKnown || s.Attributed == 0 || s.LiveWS == 0 {
		out := append([]*runRec(nil), s.RunList...)
		sort.Slice(out, func(i, j int) bool {
			if seqKey(out[i]) != seqKey(out[j]) {
				return seqKey(out[i]) < seqKey(out[j])
			}
			return out[i].start < out[j].start
		})
		return out
	}
	var live, stale []*runRec
	for _, r := range s.RunList {
		if r.live {
			live = append(live, r)
		} else if *includeStale {
			stale = append(stale, r)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].seqno < live[j].seqno })
	return append(live, stale...)
}

func addRow(m map[string]*tableStats, name, op string, sz uint64, rows int) {
	t := m[name]
	if t == nil {
		t = &tableStats{}
		m[name] = t
	}
	n := uint64(rows)
	switch op {
	case "insert":
		t.Inserts += n
	case "update":
		t.Updates += n
	case "delete":
		t.Deletes += n
	}
	t.Bytes += sz
}

func printDetail(s *summary) {
	runs := selectedRuns(s)
	if len(runs) == 0 {
		return
	}
	fmt.Printf("\n%s\n", hi("=== Write-sets ==="))
	for _, r := range runs {
		var who string
		if r.seqno > 0 {
			sz := r.bufSize
			if sz == 0 {
				sz = r.bytes()
			}
			tag := ""
			if s.RangeKnown && !r.live {
				tag = dim(" (old)")
			}
			who = fmt.Sprintf("%s %-10s %s%s",
				dim("seqno"),
				id(fmt.Sprintf("%d", r.seqno)),
				dim(fmt.Sprintf("%9d B", sz)),
				tag)
		} else {
			who = fmt.Sprintf("%s %s",
				dim(fmt.Sprintf("@0x%-9x", r.start)),
				dim(fmt.Sprintf("%9d B", r.bytes())))
		}
		if f := flagString(r); f != "" {
			who += "  " + flagColored(f)
		}
		desc := tablesDescColored(r.tables)
		if r.ddl > 0 {
			d := ddlColor(fmt.Sprintf("%d DDL", r.ddl))
			if len(r.ddlText) > 0 {
				d += dim(": "+firstLine(r.ddlText[0]))
			}
			if desc != "" {
				desc = d + dim("; ") + desc
			} else {
				desc = d
			}
		}
		fmt.Printf("  %s  %s\n", who, desc)
	}
}

func tablesDesc(tables map[string]*tableStats) string {
	if len(tables) == 0 {
		return ""
	}
	var parts []string
	for name, t := range tables {
		parts = append(parts, fmt.Sprintf("%s[i:%d u:%d d:%d]", name, t.Inserts, t.Updates, t.Deletes))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func tablesDescColored(tables map[string]*tableStats) string {
	if len(tables) == 0 {
		return ""
	}
	var parts []string
	for name, t := range tables {
		parts = append(parts, fmt.Sprintf("%s%s%s%s%s%s%s%s",
			id(name),
			dim("["),
			ins(fmt.Sprintf("i:%d", t.Inserts)),
			dim(" "),
			upd(fmt.Sprintf("u:%d", t.Updates)),
			dim(" "),
			del(fmt.Sprintf("d:%d", t.Deletes)),
			dim("]"),
		))
	}
	sort.Strings(parts)
	return strings.Join(parts, dim(", "))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func printDecode(s *summary) {
	runs := selectedRuns(s)
	total := len(runs)
	if *limit > 0 && *limit < total {
		total = *limit
	}
	progress := total > 200 // only bother for slow runs
	printed := 0
	scanned := 0
	for _, r := range runs {
		if *limit > 0 && printed >= *limit {
			break
		}
		scanned++
		if progress && (scanned%100 == 0 || scanned == total) {
			fmt.Fprintf(os.Stderr, "\rdecoding write-sets: %d/%d ...", scanned, total)
		}
		block := decodeRun(s.data, r)
		if block == "" {
			continue
		}
		if r.seqno > 0 {
			sz := r.bufSize
			if sz == 0 {
				sz = r.bytes()
			}
			tag := ""
			if s.RangeKnown && !r.live {
				tag = dim(" (older/overwritten)")
			}
			if f := flagString(r); f != "" {
				tag += " " + flagColored(f)
			}
			fmt.Printf("\n%s %s %s%s\n%s",
				dim("--"),
				dim("seqno"),
				id(fmt.Sprintf("%d", r.seqno)),
				dim(fmt.Sprintf(" (%d bytes)", sz))+tag,
				block)
		} else {
			fmt.Printf("\n%s %s %s\n%s",
				dim("--"),
				dim(fmt.Sprintf("write-set @0x%x", r.start)),
				dim(fmt.Sprintf("(%d bytes, no seqno)", r.bytes())),
				block)
		}
		printed++
	}
	if progress {
		fmt.Fprintf(os.Stderr, "\rdecoding write-sets: %d/%d done\n", scanned, total)
	}
}

func printSummary(s *summary, top int) {
	flavor := "unknown"
	switch {
	case s.SawMaria || (s.SawV1 && !s.SawV2):
		flavor = "MariaDB Galera"
	case s.SawV2:
		flavor = "PXC / MySQL 8.x"
	}

	fmt.Printf("%s\n", hi(fmt.Sprintf("=== %s %s — GCache Summary ===", appName, version)))
	fmt.Printf("%s %s\n", dim("File:   "), s.FileName)
	fmt.Printf("%s %.2f MB\n", dim("Size:   "), float64(s.TotalSize)/(1024*1024))
	fmt.Printf("%s %s   %s %s\n", dim("Version:"), fmt.Sprintf("%d", s.Version), dim("UUID:"), id(s.UUID))
	if s.RangeKnown {
		span := s.SeqnoMax - s.SeqnoMin + 1
		fmt.Printf("%s %s – %s  %s\n",
			dim("Seqno (retained): "),
			id(fmt.Sprintf("%d", s.SeqnoMin)),
			id(fmt.Sprintf("%d", s.SeqnoMax)),
			dim(fmt.Sprintf("(%d in cache)", span)))
	} else if s.Attributed > 0 {
		fmt.Printf("%s %s – %s  %s\n",
			dim("Seqno (derived):  "),
			id(fmt.Sprintf("%d", s.DerivedMin)),
			id(fmt.Sprintf("%d", s.DerivedMax)),
			warn("[preamble not synced]"))
	} else if s.HasSeqno {
		fmt.Printf("%s %s – %s  %s\n",
			dim("Seqno:            "),
			fmt.Sprintf("%d", s.SeqnoMin),
			fmt.Sprintf("%d", s.SeqnoMax),
			warn("(preamble not synced)"))
	}
	if s.Synced != "" {
		syncStr := s.Synced
		if s.Synced == "1" {
			syncStr = good("yes")
		} else {
			syncStr = warn(s.Synced)
		}
		fmt.Printf("%s %s   %s %s\n", dim("Synced: "), syncStr, dim("Offset:"), fmt.Sprintf("%d", s.Offset))
	}
	printEncryption(s)
	fmt.Printf("%s %s\n", dim("Flavor: "), id(flavor))

	// Write-set counts
	fmt.Println()
	if !s.SeqnoChecked {
		fmt.Printf("%s %s   %s\n",
			hi("Write-sets found: "), fmt.Sprintf("%d", s.Runs),
			dim("(use --detail for retained/stale split + per-write-set seqnos)"))
	} else if s.RangeKnown && s.Attributed == 0 {
		fmt.Printf("%s %s  %s\n",
			hi("Write-sets found: "), fmt.Sprintf("%d", s.Runs),
			bad("(seqno attribution failed — see --debug)"))
	} else if s.RangeKnown {
		fmt.Printf("%s %s  %s retained, %s older/overwritten\n",
			hi("Write-sets found: "), fmt.Sprintf("%d", s.Runs),
			good(fmt.Sprintf("%d", s.LiveWS)),
			dim(fmt.Sprintf("%d", s.StaleWS)))
	} else {
		fmt.Printf("%s %s  %s\n",
			hi("Write-sets found: "), fmt.Sprintf("%d", s.Runs),
			dim(fmt.Sprintf("(seqno derived for %d; retained range unknown)", s.Attributed)))
	}
	fmt.Printf("%s %s\n", hi("DDL statements:   "), ddlColor(fmt.Sprintf("%d", s.DDLCount)))
	fmt.Printf("%s %s\n", hi("GTID events seen: "), fmt.Sprintf("%d", s.GTIDs))
	scope := "all write-sets"
	if *liveOnly {
		scope = "live write-sets only"
	}
	fmt.Printf("%s %s  %s  %s\n",
		hi("Rows changed:     "),
		fmt.Sprintf("%d", s.RowsChanged),
		dim(fmt.Sprintf("(%.2f MB)", float64(s.RowBytes)/(1024*1024))),
		dim(fmt.Sprintf("[%s]", scope)))

	if *debug {
		printDebug(s)
	}

	if *summaryOnly || len(s.Tables) == 0 {
		if len(s.Tables) == 0 {
			fmt.Println()
			if s.Enc.Encrypted && !s.Decrypted {
				fmt.Printf("%s\n", warn("The cache is encrypted and was not decrypted, so no write-sets could be read."))
				fmt.Printf("%s\n", dim("Supply the master key with --keyring-file / --master-key / --vault-url."))
				return
			}
			if s.Enc.Encrypted && s.Decrypted {
				if s.EncEmptyRB {
					fmt.Printf("%s\n", good("The cache decrypted correctly, and the ring buffer is empty."))
					fmt.Printf("%s\n", dim("Only the header area after the preamble holds data; everything from start_ onward"))
					fmt.Printf("%s\n", dim("is zeros. No write-sets are persisted in this file. The seqnos a running node"))
					fmt.Printf("%s\n", dim("reports (wsrep_local_cached_downto..wsrep_last_committed) live in memory; copy the"))
					fmt.Printf("%s\n", dim("cache from a node that has flushed write traffic, or after a non-empty clean shutdown."))
					return
				}
				fmt.Printf("%s\n", good("The cache decrypted successfully, but holds no row-based write-sets."))
				fmt.Printf("%s\n", dim("Run with --debug for a byte census, or --dump-decrypted to inspect the plaintext."))
				return
			}
			fmt.Printf("%s\n", warn("No row-based write-sets were decoded."))
			fmt.Printf("%s\n", dim("If the cluster runs binlog_format=STATEMENT or the data lies in gcache.page.* files,"))
			fmt.Printf("%s\n", dim("point --file at those, or run with --debug."))
		}
		return
	}

	type kv struct {
		name string
		st   *tableStats
	}
	var ss []kv
	for k, v := range s.Tables {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].st.events() != ss[j].st.events() {
			return ss[i].st.events() > ss[j].st.events()
		}
		return ss[i].st.Bytes > ss[j].st.Bytes
	})

	fmt.Printf("\n%s %d %s\n",
		hi("Top"), top, hi("tables by row activity:"))
	// Format each cell to its fixed width FIRST, then wrap in color codes.
	// If color codes are passed to %-Ns directly, their invisible bytes eat
	// into the padding and destroy alignment.
	fmt.Printf("  %s %s %s %s %s %s\n",
		dim(fmt.Sprintf("%-40s", "table")),
		ins(fmt.Sprintf("%8s", "insert")),
		upd(fmt.Sprintf("%8s", "update")),
		del(fmt.Sprintf("%8s", "delete")),
		ddlColor(fmt.Sprintf("%6s", "ddl")),
		dim(fmt.Sprintf("%10s", "size")))
	// Separator: 40 + 1 + 8 + 1 + 8 + 1 + 8 + 1 + 6 + 1 + 10 = 85 visible chars
	fmt.Printf("  %s\n", dim(strings.Repeat("─", 85)))
	for i := 0; i < top && i < len(ss); i++ {
		t := ss[i].st
		name := fmt.Sprintf("%-40s", ss[i].name)
		nIns := fmt.Sprintf("%8d", t.Inserts)
		nUpd := fmt.Sprintf("%8d", t.Updates)
		nDel := fmt.Sprintf("%8d", t.Deletes)
		nDDL := fmt.Sprintf("%6d", t.DDLs)
		nSz := fmt.Sprintf("%10.1fM", float64(t.Bytes)/(1024*1024))
		fmt.Printf("  %s %s %s %s %s %s\n",
			id(name), ins(nIns), upd(nUpd), del(nDel), ddlColor(nDDL), dim(nSz))
	}
}

func printDebug(s *summary) {
	fmt.Printf("\n%s\n", hi("--- debug ---"))
	printEncDebug(s)
	fmt.Printf("%s\n", dim("Seqno attribution: gcache BufferHeader (size@+16, flags@+20, store@+22), seqno from header/payload"))
	fmt.Printf("  %s %s\n", dim("valid BufferHeaders found:"), fmt.Sprintf("%d", s.CandCount))
	fmt.Printf("  %s %s, %s %s",
		dim("write-sets:"), fmt.Sprintf("%d", s.Runs),
		dim("with seqno:"), fmt.Sprintf("%d", s.Attributed))
	if s.RangeKnown {
		fmt.Printf(", %s %s", dim("retained (in range):"), good(fmt.Sprintf("%d", s.LiveWS)))
	} else if s.Attributed > 0 {
		fmt.Printf(", %s %s – %s",
			dim("derived seqno range:"),
			id(fmt.Sprintf("%d", s.DerivedMin)),
			id(fmt.Sprintf("%d", s.DerivedMax)))
	}
	fmt.Printf("\n")
	if s.Attributed == 0 && len(s.RunList) > 0 {
		fmt.Printf("  %s\n", warn("(no seqnos derived; the BufferHeader layout may differ on this build)"))
		if s.RangeKnown && len(s.data) > 0 {
			dumpHeaderDiag(s)
		}
	}
	if s.Attributed > 0 {
		released, skipped, none := 0, 0, 0
		var sample uint32
		haveSample := false
		for _, r := range s.RunList {
			if !r.hasFlags {
				continue
			}
			if !haveSample {
				sample, haveSample = r.flags, true
			}
			switch {
			case r.flags&bhReleased != 0 && r.flags&bhSkipped != 0:
			case r.flags&bhReleased != 0:
				released++
			case r.flags&bhSkipped != 0:
				skipped++
			default:
				none++
			}
		}
		fmt.Printf("%s %s=%s %s=%s %s=%s",
			dim(fmt.Sprintf("Flags (read at header+%d):", s.SizeOff+4)),
			dim("RELEASED"), fmt.Sprintf("%d", released),
			dim("SKIPPED"), fmt.Sprintf("%d", skipped),
			dim("none"), fmt.Sprintf("%d", none))
		if haveSample {
			fmt.Printf("  %s", dim(fmt.Sprintf("(first raw flags word: 0x%08x)", sample)))
		}
		fmt.Printf("\n")
	}
	fmt.Printf("%s\n", hi("Event-type histogram (within decoded runs):"))
	type eh struct {
		t byte
		c uint64
	}
	var hs []eh
	for t, c := range s.EventHist {
		hs = append(hs, eh{t, c})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].c > hs[j].c })
	for _, h := range hs {
		fmt.Printf("  %s %s  %s\n",
			dim(fmt.Sprintf("type 0x%02x (%3d):", h.t, h.t)),
			fmt.Sprintf("%d", h.c),
			id(eventName(h.t)))
	}
}

// dumpHeaderDiag prints, for a synced cache where seqno attribution failed,
// enough of the raw bytes around each write-set boundary to reverse-engineer the
// provider's BufferHeader layout. It (1) shows where the in-range seqno int64s
// actually sit relative to the runs, and (2) hexdumps the start of each
// write-set's buffer region (the bytes right after the previous run ends, where
// the BufferHeader is expected to begin).
func dumpHeaderDiag(s *summary) {
	data := s.data
	lo, hi := s.SeqnoMin, s.SeqnoMax

	fmt.Printf("\n  --- header layout diagnostics (paste this back to me) ---\n")
	fmt.Printf("  in-range seqno int64s [%d..%d] and where they sit:\n", lo, hi)
	shown := 0
	for j := 0; j+8 <= len(data) && shown < 32; j++ {
		if data[j+6] != 0 || data[j+7] != 0 {
			continue
		}
		v := int64(binary.LittleEndian.Uint64(data[j : j+8]))
		if v < lo || v > hi {
			continue
		}
		rel := "after all runs"
		for i, r := range s.RunList {
			if j < r.start {
				rel = fmt.Sprintf("before run %d @0x%x (run.start-%d)", i, r.start, r.start-j)
				break
			}
			if j < r.end {
				rel = fmt.Sprintf("INSIDE run %d payload (+%d)", i, j-r.start)
				break
			}
		}
		fmt.Printf("    seqno %d @0x%x  (%s)\n", v, j, rel)
		shown++
	}

	hexdump := func(off, n int) {
		end := off + n
		if end > len(data) {
			end = len(data)
		}
		for p := off; p < end; p += 16 {
			e := p + 16
			if e > end {
				e = end
			}
			fmt.Printf("    %08x: ", p)
			for k := p; k < e; k++ {
				fmt.Printf("%02x ", data[k])
			}
			fmt.Printf("\n")
		}
	}

	// For each write-set, the BufferHeader should start in the gap that precedes
	// its binlog run (after the previous run's binlog ends).
	for i := 0; i < len(s.RunList) && i < 6; i++ {
		r := s.RunList[i]
		gs := 0
		if i > 0 {
			gs = s.RunList[i-1].end
		}
		fmt.Printf("\n  write-set %d: binlog run @0x%x..0x%x; header region starts ~0x%x (gap %d B)\n",
			i, r.start, r.end, gs, r.start-gs)
		// scan the gap for any plausible seqno-magnitude int64 (helps if the
		// seqno is stored offset/encoded rather than as the bare value).
		near := 0
		for j := gs; j+8 <= r.start && near < 6; j++ {
			if data[j+6] != 0 || data[j+7] != 0 {
				continue
			}
			v := int64(binary.LittleEndian.Uint64(data[j : j+8]))
			if v > 0 && v < hi+1_000_000 {
				fmt.Printf("    int64 %d @0x%x (gap+%d, run.start-%d)\n", v, j, j-gs, r.start-j)
				near++
			}
		}
		fmt.Printf("    first 96 bytes at header region start:\n")
		hexdump(gs, 96)
	}
	fmt.Printf("  --- end diagnostics ---\n")
}

func eventName(t byte) string {
	switch t {
	case evQuery:
		return "QUERY"
	case evXID:
		return "XID"
	case evTableMap:
		return "TABLE_MAP"
	case evWriteRowsV1, evWriteRowsV2:
		return "WRITE_ROWS"
	case evUpdateRowsV1, evUpdateRowsV2:
		return "UPDATE_ROWS"
	case evDeleteRowsV1, evDeleteRowsV2:
		return "DELETE_ROWS"
	case evGTIDLog:
		return "GTID_LOG (MySQL)"
	case evMariaGTID:
		return "GTID (MariaDB)"
	case evAnnotateRows:
		return "ANNOTATE_ROWS (MariaDB)"
	case evWriteRowsCompV1:
		return "WRITE_ROWS_COMPRESSED"
	case evUpdateRowsCompV1:
		return "UPDATE_ROWS_COMPRESSED"
	case evDeleteRowsCompV1:
		return "DELETE_ROWS_COMPRESSED"
	}
	return ""
}
