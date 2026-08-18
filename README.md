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
- Dates each write-set from the commit timestamp in its binlog image, and reports
  the time span the cache covers.
- Prints the seqno range actually present, so a specific seqno or window can then
  be selected with `--seqno`.
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
| `--no-summary` | Skip the summary entirely (header *and* tables); print only `--detail` / `--decode-rows` output. |
| `--detail` | List each write-set: seqno, buffer size, RELEASED/SKIPPED flags, table ops, DDL. |
| `--decode-rows` | Decode each row event into `mysqlbinlog DECODE-ROWS -v` style output. |
| `--limit N` | Max write-sets to list (`--detail`) or decode (`--decode-rows`); 0 = all. Ignored when `--seqno` is used. |
| `--seqno SPEC` | Restrict `--detail` / `--decode-rows` to selected seqnos (see below). Implies `--detail`. |
| `--utc` | Print write-set timestamps in UTC instead of local time. |
| `--include-stale` | Also include stale write-sets (leftovers from earlier ring-buffer cycles). |
| `--live-only` | Restrict table/row aggregates to retained write-sets only. |
| `--fast` | Skip the buffer-header scan: no seqnos, flags or retained/stale split, roughly twice as fast. |
| `--no-progress` | Never draw the progress bar (also honoured: `NO_PROGRESS=1`). |
| `--debug` | Show the event-type histogram and seqno/flags auto-calibration diagnostics. |
| `--version` | Print version and exit. |

### Selecting write-sets

The summary prints the seqno range actually present in the cache, which is what
you feed back into `--seqno`:

| Spec | Meaning |
|------|---------|
| `--seqno 1234` | just that write-set |
| `--seqno 1200-1300` | a closed range (`1200..1300` works too) |
| `--seqno 1200-` | from 1200 to the end of the cache |
| `--seqno -1300` | from the start of the cache to 1300 |
| `--seqno 12,50-60,900-` | any comma-separated mix of the above |

A `--seqno` selection is honoured regardless of whether the write-set is still
retained, so naming an older/overwritten seqno explicitly still decodes it.

### Encrypted caches

When `gcache_encrypt=ON`, the preamble stays in the clear but the ring buffer is
encrypted with a File Key, which is itself wrapped with the keyring's Master Key.
Supply the master key by any of these routes:

| Flag | Description |
|------|-------------|
| `--keyring-file PATH` | Read the master key from a keyring component file (JSON). |
| `--master-key HEX` | Give the master key directly (64 hex chars for AES-256). |
| `--vault-url URL` | Fetch it from HashiCorp Vault (with `--vault-token` / `--vault-token-file`, `--vault-mount`, `--vault-path`, `--vault-namespace`, `--vault-insecure`). |
| `--file-key HEX` | Use an already-unwrapped File Key, skipping the master key entirely. |
| `--no-prompt` | Never ask interactively for key material (for scripts and cron). |

With none of these, the tool asks once, interactively. Diagnostics and manual
overrides:

| Flag | Description |
|------|-------------|
| `--dump-preamble` | Print the raw preamble (text + hexdump) and exit. |
| `--enc-probe` | Analyse the encrypted layout without any key, print findings and exit. |
| `--dump-decrypted PATH` | After decrypting, write the plaintext image to `PATH` for offline inspection. |
| `--enc-scheme S` | Pin the cipher layout instead of auto-detecting it. |
| `--enc-page-size N` | Pin the encryption page size in bytes (0 = auto). |
| `--enc-base OFF` | Pin the file offset where the encrypted region starts (-1 = auto). |

A file written by `--dump-decrypted` keeps the original preamble byte for byte,
including its `enc_*` keys — the preamble was never encrypted, so there is
nothing there to change. Such an image therefore still *advertises* encryption
while its payload is already in the clear. `gcache-inspector` detects this and
reads the dump without asking for a key, reporting:

```
Encrypted: per preamble, but this image is already plaintext
Note:      no key needed — the preamble is copied verbatim into a --dump-decrypted image
```

The detection requires positive evidence (framed write-sets in regions that were
actually written), so a genuinely encrypted cache is never mistaken for a
plaintext one.

### Progress

Long scans (a 1 GB cache takes a few seconds per pass) draw a progress bar on
**stderr**, so `--decode-rows > decoded.txt` still writes a clean file. Nothing
is drawn when stderr is not a terminal, or when the work finishes in under
~150 ms, so scripted use is unaffected.

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

Look at one transaction, or a window around it, once the summary has told you
which seqnos are in the cache:

```sh
gcache-inspector --file galera.cache --seqno 1109
gcache-inspector --file galera.cache --seqno 1100-1109 --decode-rows
```

Row images only, with no summary at all — handy when feeding the output to
another tool:

```sh
gcache-inspector --file galera.cache --decode-rows --no-summary > rows.sql
```

Decrypt once, then work on the plaintext copy without touching the keyring
again:

```sh
gcache-inspector --file galera.cache --keyring-file /var/lib/mysql-keyring/component_keyring_file \
    --dump-decrypted /tmp/plain.cache --summary-only
gcache-inspector --file /tmp/plain.cache --decode-rows --seqno 4400-4410
```

## Output notes

- **Retained vs stale.** The GCache is a ring buffer; once it has wrapped it
  still contains decodable fragments of older, already-overwritten write-sets.
  When the preamble carries a valid seqno range, write-sets inside it are
  "retained" and the rest are "older/overwritten". On a live (unsynced) node the
  preamble range may be absent, in which case seqnos are derived from the headers
  and labeled accordingly.
- **Timestamps** come from the binlog event header carried inside each write-set,
  i.e. the commit time on the node that *executed* the transaction. Resolution is
  one second and the clock is that node's, not the local one. They appear per
  write-set under `--detail` / `--decode-rows` and as an overall `Time range` in
  the summary; `--utc` switches from local time. A write-set whose header holds
  no plausible time (zero, pre-2010, or in the future) is simply left undated.
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
