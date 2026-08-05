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
- Detects encrypted caches (`gcache.encryption=ON`), resolves the master key from
  a keyring component file or HashiCorp Vault, unwraps the file key from the
  preamble and decrypts the ring buffer in memory before analyzing it.

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

Flags for encrypted caches:

| Flag | Description |
|------|-------------|
| `--keyring-file PATH` | Keyring **component** file (JSON) holding the GCache master key. |
| `--master-key HEX` | Master key given directly, as hex (64 chars for AES-256). |
| `--vault-url URL` | HashiCorp Vault address (default `$VAULT_ADDR`). |
| `--vault-token TOKEN` / `--vault-token-file PATH` | Vault token (default `$VAULT_TOKEN`). |
| `--vault-mount NAME` | KV mount holding the keyring secrets (default `secret`). |
| `--vault-path PATH` | Explicit Vault path to the master key, overriding `--vault-mount`. |
| `--vault-namespace NS` | Vault namespace header, if any. |
| `--vault-insecure` | Skip TLS verification when talking to Vault. |
| `--dump-preamble` | Print the raw preamble (text + hexdump) and exit. |
| `--enc-probe` | Analyze the encrypted layout without any key (base offset, written region, keystream period) and exit. |
| `--file-key HEX` | Use this file key directly, skipping master-key unwrapping. |
| `--dump-decrypted PATH` | After decrypting, write the plaintext image to PATH for offline inspection. |
| `--enc-scheme S` | Pin the cipher layout instead of auto-detecting it. |
| `--enc-page-size N` | Pin the encryption page size (bytes). |
| `--enc-base OFF` | Pin the file offset where the encrypted region starts. |
| `--no-prompt` | Never ask interactively for key material. |

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

## Encrypted caches

With `gcache.encryption=ON` (PXC 8.0.31+ / 8.4, tech preview) the RingBuffer is
encrypted with a random per-file key. That file key is itself encrypted with a
master key kept in the server's keyring, and the wrapped file key is stored in
the cache preamble, which stays in clear text. The preamble therefore tells us
everything except the key itself:

```
EncVersion: 1
Encrypted: 1
MasterKeyConst UUID: 62eff734-8de5-11f1-b956-7f3a785ad5e2
MasterKey UUID: d6945297-8f7a-11f1-9533-7a5bf82f508c
MasterKey ID: 1
```

`gcache-inspector` detects this automatically and reports it in the summary. To
decrypt, point it at the keyring component file:

```sh
gcache-inspector --file galera.cache \
  --keyring-file /var/lib/mysql-keyring/component_keyring_file
```

The master key is the keyring element whose `data_id` is
`GaleraKey-<MasterKey UUID>@<MasterKeyConst UUID>-<MasterKey ID>`, e.g.

```
GaleraKey-d6945297-8f7a-11f1-9533-7a5bf82f508c@62eff734-8de5-11f1-b956-7f3a785ad5e2-1
```

The tool looks that entry up by name; if the preamble refers to a rotated key
that is no longer in the keyring it falls back to the newest `GaleraKey-*` entry
and says so. You can also skip the keyring entirely with `--master-key <hex>`,
or read the key from Vault:

```sh
gcache-inspector --file galera.cache \
  --vault-url https://vault.example.com:8200 --vault-token-file ~/.vault-token
```

If the file is encrypted and no key source was given, the tool asks for one
interactively (unless `--no-prompt` is set or stdout is not a terminal).

### The cipher layout

The scheme is confirmed against Percona's provider sources
(`galerautils/src/gu_enc_mmap.cpp`, `gcache/src/gcache_rb_store.cpp`):

- **AES-CTR with an all-zero IV.** `EncMMap::set_key()` opens an
  `Aes_ctr_encryptor` with `iv[AES_BLOCK_SIZE] = {0}` and the raw file key.
- **One continuous stream over the whole file.** `EncMMap::decrypt()` calls
  `set_stream_offset(page_start_offset + unencrypted_size)`, an *absolute* file
  offset, so the keystream position of any byte is simply its offset in the
  file. The mmap page size therefore affects performance, not the ciphertext.
- **The preamble is stored in clear but still consumes stream positions.**
  `RingBuffer` passes `PREAMBLE_LEN` as the factory's `encryption_start_offset`,
  and bytes below it are `memcpy`-ed rather than encrypted.
- **The file key** is `decrypt_key(decode64(enc_fk_id), master_key)`, which is
  itself AES-CTR with an all-zero IV using the master key raw
  (`galerautils/src/gu_enc_utils.cpp`). It asserts that both keys are exactly
  `FILE_KEY_LENGTH` (32) bytes, so the keyring value is used as decoded bytes.

The tool implements exactly that, but still verifies rather than assumes: it
decrypts sample windows and scores each candidate derivation. Two signals are
used. Never-written parts of the pre-allocated ring buffer hold *encrypted
zeros*, so the correct key turns them straight back into zeros while any wrong
key yields keystream — an unambiguous check that works even on a cache holding
few write-sets. Written regions are scored on plaintext structure: binlog
`TABLE_MAP` events with real identifiers and GCache `BufferHeader` signatures.
The winner is reported with the derivation that produced it:

```
Cipher:    AES-256-ctr-file, clear below 0x1000, counter from 0x0 [CTR unwrap (zero IV), keyring bytes]
```

If no derivation works, the tool falls back to a wide search over cipher modes,
page sizes and counter origins, in case a build differs from these sources.
`--file-key <hex>` skips the unwrapping entirely, and `--enc-probe` reports the
layout fingerprints the file leaks without any key at all: where the clear
preamble ends, how much of the ring buffer was ever written, and whether the
ciphertext repeats (which would indicate a per-page keystream rather than the
continuous one).

### When a decrypted cache shows no write-sets

If the summary reports `Encrypted: yes — decrypted (ring buffer empty)`, the file
decrypted correctly but contains no persisted write-sets. A GCache file is
pre-allocated to its full size; with encryption on, the unused space is stored as
encrypted zeros, so the correct key turns the whole ring buffer back into zeros.
The only non-zero bytes are the plaintext preamble and a small fixed-size header
area right after it (the `header_` array, before `start_`). This is the normal
state of a freshly-initialized or cleanly-reset buffer.

Note that the seqno range a *running* node reports (`wsrep_local_cached_downto`
through `wsrep_last_committed`) reflects its in-memory cache, which is not
necessarily flushed to `galera.cache` on disk. To inspect real write-sets, copy
the cache from a node that has flushed write traffic, or capture it while the
node is actively replicating. `--dump-decrypted` writes the plaintext image so
you can confirm the buffer state with `xxd` directly.

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

### Encrypted caches lag a running node (write-back cache)

On a node with `gcache.encryption=ON`, the `galera.cache` file on disk does **not**
update in real time the way an unencrypted cache does. This is expected and is a
property of how the provider encrypts the ring buffer, not a bug in this tool.

An unencrypted GCache is a plain `mmap` of the file: the kernel page cache writes
dirty pages back to disk continuously, so new DMLs appear almost immediately and
the file's `md5sum` changes as you write.

An encrypted GCache cannot work that way, because the bytes in memory are
plaintext but the bytes on disk must be ciphertext. The provider therefore
interposes its own **user-space write-back page cache** (`EncMMap`): the live
ring buffer lives in anonymous memory as plaintext, and a page is only encrypted
and written to the file when it is *evicted* from that cache or when the mapping
is *synced*. The cache is sized by `encryption_cache_size` (16 MB in the example
below) in `encryption_cache_page_size` pages (32 KB). As long as the working set
of active write-sets fits in that cache, **nothing is flushed to the file**, so:

- the file's `md5sum` stays constant while the node keeps writing, and
- this tool, reading the file offline, shows a stalled seqno range until a flush
  happens.

A flush (and therefore an up-to-date file) is triggered by page eviction under
cache pressure, by a clean shutdown/restart (`sync_on_destroy`), or by an
internal `sync()`. This is why restarting the PXC node made the new write-sets
appear: shutdown flushed and re-`write_preamble`-d the whole buffer.

Practical implication: to inspect the *current* state of an encrypted cache from
a busy node, capture it after a flush — a clean restart is the reliable one. A
copy taken mid-run reflects only what has been evicted so far, which for a small
workload can be nothing. With `encryption_cache_size = 16 MB` and a ~160 KB
working set, the entire cache stays resident and the file effectively never
changes until shutdown. The tool now prints a `Freshness:` note whenever it
decodes an encrypted cache, as a reminder that the file may trail the live node.

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
- Encrypted GCache off-pages (`gcache.page.*`) and Write-Set cache files cannot
  be decrypted at all: their file keys are random per file and are never stored
  anywhere, by design. Only the RingBuffer keeps its (wrapped) file key.
- Decryption holds both the ciphertext and the plaintext in memory, so peak
  usage is roughly twice the cache size.
- The binary `keyring_file` *plugin* format is not read; use a keyring
  *component* file (JSON) or pass `--master-key`.
- Large transactions stored in `gcache.page.*` files are not in `galera.cache`;
  point `--file` at those page files to inspect them (same payload format).

## Compatibility

Tested against caches from Percona XtraDB Cluster 8.0/8.4. The binlog-event
decoding also covers MariaDB-style v1 row events and `ANNOTATE_ROWS`. Behavior
may vary across provider versions; `--debug` reports what was detected.

Encrypted-cache decoding is verified end-to-end against PXC 8.4.10
(`gcache.encryption=ON`): the tool decrypts the ring buffer, attributes each
write-set to its Galera seqno, and the recovered range and per-table row counts
match the node's own recovery log. Note that write-sets are only present on disk
once the provider has flushed them there (e.g. after a clean restart, which
writes `Synced: 1` with a real seqno range and `Offset`); a cache captured
mid-run may still be header-only, in which case the summary reports the ring
buffer as empty.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Copyright (C) 2026 Przemysław Malkowski

## Acknowledgements

The on-disk and binlog-event formats were cross-referenced against the public
documentation for the Galera provider and the MySQL/MariaDB binary-log event
format. This project is not affiliated with Codership, Percona, Oracle, or
MariaDB.
