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

// tstamp.go dates a write-set.
//
// The GCache BufferHeader carries no time at all - but the write-set payload is
// a binlog image, and every binlog event begins with a 4-byte little-endian Unix
// timestamp (seconds) written by the node that executed the transaction. That is
// exactly the time mysqlbinlog prints as "#250815  9:44:51", so taking it from
// the first event of a write-set dates the write-set itself.
//
// Resolution is therefore one second, and the clock is the *origin* node's
// clock, not the local one. Values that can't be a real commit time (zero,
// pre-2010, or in the future) are rejected, so junk that merely looks like an
// event never produces a bogus date.

import (
	"encoding/binary"
	"fmt"
	"time"
)

// tsFloor rejects timestamps before 2010-01-01; no Galera cache is that old and
// binary junk frequently decodes to small integers.
const tsFloor int64 = 1262304000

// tsCeil rejects timestamps in the future (a day of slack for clock skew).
var tsCeil = time.Now().Unix() + 86400

// eventTime returns the Unix timestamp from the common header of the binlog
// event at p, or 0 when it is missing or implausible.
func eventTime(d []byte, p int) int64 {
	if p < 0 || p+4 > len(d) {
		return 0
	}
	v := int64(binary.LittleEndian.Uint32(d[p : p+4]))
	if v < tsFloor || v > tsCeil {
		return 0
	}
	return v
}

// fmtTime renders a write-set timestamp for per-write-set output (no zone, to
// keep lines short - the zone is stated once in the summary header).
func fmtTime(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return tsIn(unix).Format("2006-01-02 15:04:05")
}

// fmtTimeZone renders a timestamp with its zone, for the summary.
func fmtTimeZone(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return tsIn(unix).Format("2006-01-02 15:04:05 MST")
}

func tsIn(unix int64) time.Time {
	t := time.Unix(unix, 0)
	if *utcTimes {
		return t.UTC()
	}
	return t.Local()
}

// fmtSpan renders the distance between two timestamps as "2h13m5s".
func fmtSpan(from, to int64) string {
	if from <= 0 || to < from {
		return ""
	}
	d := time.Duration(to-from) * time.Second
	if d == 0 {
		return "0s"
	}
	return d.String()
}

// fmtAgo renders how long ago a timestamp is, e.g. "3m ago".
func fmtAgo(unix int64) string {
	if unix <= 0 {
		return ""
	}
	d := time.Since(time.Unix(unix, 0))
	switch {
	case d < 0:
		return "in the future"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm ago", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd ago", int(d.Hours())/24)
}
