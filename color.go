// gcache-inspector - decode and summarize a Galera write-set cache (galera.cache).
//
// Copyright (C) 2026 Przemysław Malkowski
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// colorEnabled is set once at startup. We honour NO_COLOR (https://no-color.org)
// and skip colours when stdout is not a real terminal (pipe, redirect, etc.).
var colorEnabled bool

func initColor() {
	if os.Getenv("NO_COLOR") != "" {
		colorEnabled = false
		return
	}
	colorEnabled = isTTY(os.Stdout)
}

// isTTY reports whether f is a real terminal using the TIOCGWINSZ ioctl, which
// is available on Linux and macOS and requires no external package.
func isTTY(f *os.File) bool {
	var ws [4]uint16 // struct winsize: ws_row, ws_col, ws_xpixel, ws_ypixel
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TIOCGWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	return errno == 0
}

// ANSI SGR escape sequences.
const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiDim       = "\033[2m"
	ansiRed       = "\033[31m"
	ansiGreen     = "\033[32m"
	ansiYellow    = "\033[33m"
	ansiBlue      = "\033[34m"
	ansiMagenta   = "\033[35m"
	ansiCyan      = "\033[36m"
	ansiWhite     = "\033[37m"
	ansiBoldWhite = "\033[1;37m"
	ansiBoldCyan  = "\033[1;36m"
)

func col(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

// Semantic colour helpers — use these in printing code, not raw codes.

// hi renders a prominent section header / label (bold white).
func hi(s string) string { return col(ansiBold, s) }

// id renders an identifier: table name, UUID, seqno (bold cyan).
func id(s string) string { return col(ansiBoldCyan, s) }

// ins renders an insert count (green).
func ins(s string) string { return col(ansiGreen, s) }

// upd renders an update count (yellow).
func upd(s string) string { return col(ansiYellow, s) }

// del renders a delete count (red).
func del(s string) string { return col(ansiRed, s) }

// ddlColor renders a DDL count / label (magenta).
func ddlColor(s string) string { return col(ansiMagenta, s) }

// dim renders secondary / diagnostic text (dim).
func dim(s string) string { return col(ansiDim, s) }

// warn renders a warning or anomaly (bold yellow).
func warn(s string) string { return col(ansiYellow+"\033[1m", s) }

// good renders a positive status (bold green).
func good(s string) string { return col(ansiGreen+"\033[1m", s) }

// bad renders an error / not-found status (bold red).
func bad(s string) string { return col(ansiRed+"\033[1m", s) }

// flag renders a buffer-flag string (dim cyan for "-", yellow for RELEASED, red for SKIPPED).
func flagColored(s string) string {
	if !colorEnabled || s == "" {
		return s
	}
	switch s {
	case "-":
		return col(ansiDim, s)
	default:
		return col(ansiYellow, s)
	}
}
