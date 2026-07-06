# 🦬 gcache-inspector

`gcache-inspector` is an offline reader for the Galera write-set cache file
(`galera.cache` / GCache) used by Percona XtraDB Cluster (PXC 8.0/8.4) and
MariaDB Galera Cluster. It summarizes what is cached — which tables changed and
how often — and can decode individual write-sets into row-level output similar
to `mysqlbinlog --base64-output=DECODE-ROWS -v`.

It reads the file directly and does not connect to a running server, so it is
safe to point at a copy of a cache from a node that is up or down.

## What it does

- Parses the GCache preamble (version, cluster UUID, retained seqno range, sync state).
- Scans the file for write-set payloads (which are binlog row-event images) and
  builds a per-table activity summary: inserts, updates, deletes, DDL, and bytes.
- Attributes each write-set to its Galera seqno by locating the buffer header
  that frames it, and separates retained write-sets from stale leftovers of
  earlier ring-buffer cycles.
- Optionally decodes every row event into readable `### INSERT/UPDATE/DELETE`
  output, including before/after images for updates.
- Detects DDL (replicated as `QUERY` events) and attributes it to its target table.

## How it works (brief)

A row-based Galera write-set carries a binlog image of the rows it changed, so
table identity lives in embedded `TABLE_MAP` events and the operation type in the
`WRITE/UPDATE/DELETE_ROWS` events that follow — exactly what `mysqlbinlog` reads.
`gcache-inspector` scans for those events directly, which keeps it robust across
PXC/MySQL (v2 row events) and MariaDB (v1 row events). The Galera seqno and the
buffer flags live in the GCache `BufferHeader` that precedes each write-set; the
tool locates that header by framing and auto-detects the header's size-field
offset from the data rather than assuming a fixed struct layout.

## DEMO

<table>
  <tr>
    <td align="center"><img src="demo.gif" alt="demo session" width="800" /></td>
  </tr>
</table>

## Build

Requires Go 1.21+.

```sh
go build -o gcache-inspector .
```

This produces a single static binary with no external dependencies.

## Usage

```
gcache-inspector --file /path/to/galera.cache [options]
```

| Flag | Description |
|------|-------------|
| `--file PATH` | Path to the `galera.cache` file (required). |
| `--top N` | Number of top tables to show (default 10). |
| `--summary-only` | Print only the header summary, skip the table breakdown. |
| `--detail` | List each write-set: seqno, buffer size, RELEASED/SKIPPED flags, table ops, DDL. |
| `--decode-rows` | Decode each row event into `mysqlbinlog DECODE-ROWS -v` style output. |
| `--limit N` | When decoding, cap the number of write-sets printed (0 = all). |
| `--include-stale` | Also include stale write-sets (leftovers from earlier ring-buffer cycles). |
| `--live-only` | Restrict table/row aggregates to retained write-sets only. |
| `--debug` | Show the event-type histogram and seqno/flags auto-calibration diagnostics. |
| `--version` | Print version and exit. |

Note: `--detail`, `--decode-rows`, and `--debug` perform the buffer-header scan
needed for seqno/flags attribution. The plain summary skips it and stays fast.

## Examples

Quick summary with the busiest tables:

```sh
gcache-inspector --file /var/lib/mysql/galera.cache
```

Per-write-set listing with seqno, size and flags:

```sh
gcache-inspector --file galera.cache --detail
```

Decode all retained write-sets to a file (progress is shown on stderr):

```sh
gcache-inspector --file galera.cache --decode-rows > decoded.txt
```

Decode just the first 50 write-sets:

```sh
gcache-inspector --file galera.cache --decode-rows --limit 50
```

## Output notes

- **Retained vs stale.** The GCache is a ring buffer; once it has wrapped it
  still contains decodable fragments of older, already-overwritten write-sets.
  When the preamble carries a valid seqno range, write-sets inside it are
  "retained" and the rest are "older/overwritten". On a live (unsynced) node the
  preamble range may be absent, in which case seqnos are derived from the headers
  and labeled accordingly.
- **Row counts** are counts of row *events* per table, not exact row counts (a
  single event can carry many rows).
- **Columns** are shown positionally (`@1`, `@2`, ...) because column names are
  not present in the binlog unless `binlog_row_metadata=FULL`.

## Limitations

- Cannot compile/connect to a server; it is a pure offline file reader.
- `JSON` and `GEOMETRY` column values are shown as size placeholders rather than
  fully decoded.
- Unsigned integers are currently displayed as signed (the `SIGNEDNESS` optional
  metadata is not yet parsed).
- The seqno/flags attribution relies on locating the GCache `BufferHeader`. The
  size-field offset is auto-detected, but the flags-field position is assumed to
  follow the canonical `gcache_bh.hpp` layout; use `--debug` to sanity-check it on
  your build.
- Large transactions stored in `gcache.page.*` files are not in `galera.cache`;
  point `--file` at those page files to inspect them (same payload format).

## Compatibility

Tested against caches from Percona XtraDB Cluster 8.0/8.4. The binlog-event
decoding also covers MariaDB-style v1 row events and `ANNOTATE_ROWS`. Behavior
may vary across provider versions; `--debug` reports what was detected.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Copyright (C) 2026 Przemysław Malkowski

## Acknowledgements

The on-disk and binlog-event formats were cross-referenced against the public
documentation for the Galera provider and the MySQL/MariaDB binary-log event
format. This project is not affiliated with Codership, Percona, Oracle, or
MariaDB.
