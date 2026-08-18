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

// seqno.go parses --seqno, which narrows --detail / --decode-rows to the
// write-sets the user actually cares about. The summary prints the seqno range
// that is present in the cache, so the normal workflow is: run the summary, pick
// a seqno or a window from it, then re-run with --seqno.
//
// Accepted forms (comma-separated, any mix):
//
//	--seqno 1234           one write-set
//	--seqno 1200-1300      closed range (1200..1300, inclusive)
//	--seqno 1200..1300     same, if you prefer the range syntax
//	--seqno 1200-          from 1200 to the end of the cache
//	--seqno -1300          from the start of the cache to 1300
//	--seqno 12,50-60,900-  any combination of the above

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

type seqRange struct{ lo, hi int64 }

type seqnoFilter struct{ rs []seqRange }

// parseSeqnoSpec turns the --seqno string into a filter. It returns (nil, nil)
// for an empty spec, meaning "no filtering".
func parseSeqnoSpec(spec string) (*seqnoFilter, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	f := &seqnoFilter{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		loStr, hiStr := part, part
		if i := strings.Index(part, ".."); i >= 0 {
			loStr, hiStr = part[:i], part[i+2:]
		} else if i := strings.Index(part, "-"); i >= 0 {
			loStr, hiStr = part[:i], part[i+1:]
		}
		r := seqRange{lo: 1, hi: math.MaxInt64}
		var err error
		if s := strings.TrimSpace(loStr); s != "" {
			if r.lo, err = strconv.ParseInt(s, 10, 64); err != nil {
				return nil, fmt.Errorf("bad seqno %q in --seqno %q", s, spec)
			}
		}
		if s := strings.TrimSpace(hiStr); s != "" {
			if r.hi, err = strconv.ParseInt(s, 10, 64); err != nil {
				return nil, fmt.Errorf("bad seqno %q in --seqno %q", s, spec)
			}
		}
		if r.lo < 1 || r.hi < r.lo {
			return nil, fmt.Errorf("empty or reversed seqno range %q", part)
		}
		f.rs = append(f.rs, r)
	}
	if len(f.rs) == 0 {
		return nil, nil
	}
	return f, nil
}

// match reports whether a seqno is selected. A nil filter selects everything.
func (f *seqnoFilter) match(seqno int64) bool {
	if f == nil {
		return true
	}
	for _, r := range f.rs {
		if seqno >= r.lo && seqno <= r.hi {
			return true
		}
	}
	return false
}

// String renders the filter back for messages.
func (f *seqnoFilter) String() string {
	if f == nil {
		return ""
	}
	var parts []string
	for _, r := range f.rs {
		switch {
		case r.lo == r.hi:
			parts = append(parts, strconv.FormatInt(r.lo, 10))
		case r.hi == math.MaxInt64:
			parts = append(parts, fmt.Sprintf("%d and up", r.lo))
		default:
			parts = append(parts, fmt.Sprintf("%d-%d", r.lo, r.hi))
		}
	}
	return strings.Join(parts, ", ")
}
