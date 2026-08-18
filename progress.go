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

// progress.go implements the "the tool is not hung" feedback: a real progress
// bar for the phases whose total is known up front (file read, write-set scan,
// BufferHeader scan, decode), and a plain spinner for the ones that aren't
// (decryption).
//
// Everything goes to stderr, so the usual "--decode-rows > decoded.txt" keeps a
// clean file while still showing progress on the terminal. Nothing is drawn at
// all when stderr is not a TTY, so piping stays byte-identical to before.

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// progEnabled is set once at startup, after flag parsing.
var progEnabled bool

func initProgress() {
	if *noProgress || os.Getenv("NO_PROGRESS") != "" {
		progEnabled = false
		return
	}
	progEnabled = isTTY(os.Stderr)
}

const (
	progMinBytes = 8 << 20                // don't decorate small files
	progMinItems = 100                    // ... or short loops
	progDelay    = 150 * time.Millisecond // hides the flicker on fast runs
	progTick     = 100 * time.Millisecond // redraw interval
	progWidth    = 24                     // bar width in cells
	progStep     = 1 << 16                // how often hot loops report (bytes)
)

var spinFrames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// prog is one progress indicator. total == 0 means "unknown" -> spinner only.
// A prog that was never activated (not a TTY, too small) is still safe to use;
// every method is then a no-op, so callers need no conditionals.
type prog struct {
	label string
	total int64
	items bool // total counts items rather than bytes
	cur   atomic.Int64
	start time.Time
	stop  chan struct{}
	done  chan struct{}
	on    bool
}

// newProgBytes returns a byte-oriented progress bar.
func newProgBytes(label string, total int64) *prog {
	return newProg(label, total, false, progMinBytes)
}

// newProgItems returns a count-oriented progress bar ("42/900").
func newProgItems(label string, total int64) *prog {
	return newProg(label, total, true, progMinItems)
}

// newSpinner returns an indeterminate indicator for work of unknown length.
func newSpinner(label string) *prog {
	return newProg(label, 0, false, 0)
}

func newProg(label string, total int64, items bool, minTotal int64) *prog {
	p := &prog{label: label, total: total, items: items, start: time.Now()}
	if !progEnabled || (total > 0 && total < minTotal) {
		return p
	}
	p.on = true
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	go p.run()
	return p
}

// set reports the current position. Cheap enough to call from a scan loop
// (one atomic store), but callers still throttle it to every progStep bytes.
func (p *prog) set(n int64) {
	if p.on {
		p.cur.Store(n)
	}
}

// finish stops the drawing goroutine and wipes the line. Safe to call twice,
// which lets callers both defer it and call it explicitly before printing.
func (p *prog) finish() {
	if !p.on {
		return
	}
	p.on = false
	close(p.stop)
	<-p.done
	fmt.Fprint(os.Stderr, "\r\033[2K")
}

func (p *prog) run() {
	defer close(p.done)
	select { // stay silent if the work finishes almost immediately
	case <-p.stop:
		return
	case <-time.After(progDelay):
	}
	t := time.NewTicker(progTick)
	defer t.Stop()
	for i := 0; ; i++ {
		p.draw(spinFrames[i%len(spinFrames)])
		select {
		case <-p.stop:
			return
		case <-t.C:
		}
	}
}

func (p *prog) draw(spin string) {
	if p.total <= 0 {
		fmt.Fprintf(os.Stderr, "\r\033[2K%s %s  %s", spin, p.label, progElapsed(p.start))
		return
	}
	cur := p.cur.Load()
	if cur > p.total {
		cur = p.total
	}
	frac := float64(cur) / float64(p.total)
	filled := int(frac*progWidth + 0.5)
	if filled > progWidth {
		filled = progWidth
	}
	amount := fmt.Sprintf("%s / %s", progHumanBytes(cur), progHumanBytes(p.total))
	if p.items {
		amount = fmt.Sprintf("%d / %d", cur, p.total)
	}
	fmt.Fprintf(os.Stderr, "\r\033[2K%s %s [%s%s] %3.0f%%  %s  %s",
		spin, p.label,
		strings.Repeat("█", filled), strings.Repeat("░", progWidth-filled),
		frac*100, amount, progElapsed(p.start))
}

func progElapsed(start time.Time) string {
	return fmt.Sprintf("%4.1fs", time.Since(start).Seconds())
}

func progHumanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// readFileProgress is os.ReadFile with a progress bar: on a 1 GB cache the read
// itself is a noticeable part of the wall time, and it is the very first thing
// that happens, so without it the tool looks frozen on start.
func readFileProgress(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if !fi.Mode().IsRegular() || size <= 0 {
		return io.ReadAll(f) // pipe, device, /proc entry: length unknown
	}

	buf := make([]byte, size)
	pr := newProgBytes("reading cache", size)
	defer pr.finish()

	const chunk = 8 << 20
	var off int64
	for off < size {
		end := off + chunk
		if end > size {
			end = size
		}
		n, rerr := io.ReadFull(f, buf[off:end])
		off += int64(n)
		pr.set(off)
		if rerr != nil {
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				return buf[:off], nil // file shrank under us; use what we got
			}
			return nil, rerr
		}
	}
	return buf, nil
}
