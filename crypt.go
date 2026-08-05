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

// crypt.go adds support for encrypted GCache RingBuffer files (PXC 8.0.31+ /
// 8.4 with gcache.encryption=ON).
//
// What Percona documents about the scheme:
//
//   - The RingBuffer file is encrypted with a random per-file key ("File Key").
//   - The File Key is encrypted with a Master Key that lives in the server's
//     keyring component/plugin, and the *encrypted* File Key is stored in the
//     RingBuffer preamble.
//   - Encryption happens on the mmap layer, in fixed-size pages
//     (gcache.encryption_cache_page_size, default 32 KB, always a multiple of
//     the 4 KB CPU page size), so the file must be randomly addressable.
//   - The preamble itself stays in clear text.
//
// The preamble spellings differ between builds. PXC 8.0 writes lower-case keys
//
//     enc_version / enc_encrypted / enc_mk_id / enc_mk_const_id / enc_mk_uuid /
//     enc_fk_id / enc_crc
//
// while PXC 8.4 prints (and writes) the friendlier
//
//     EncVersion / Encrypted / MasterKey ID / MasterKeyConst UUID /
//     MasterKey UUID / ...
//
// so preamble keys are normalized (lower-cased, punctuation stripped) before
// matching, and the wrapped File Key is picked up from whatever key name the
// build uses, as long as it mentions "fk" or "filekey".
//
// The keyring entry that holds the Master Key is named
//
//     GaleraKey-<MasterKey UUID>@<MasterKeyConst UUID>-<MasterKey ID>
//
// which for a keyring component file is the "data_id" of one of the elements,
// with "data" holding the AES key as hex.
//
// What Percona does *not* document is the exact cipher mode and IV derivation
// used for the pages, nor how the File Key is wrapped with the Master Key.
// Rather than guess once and be silently wrong, this file treats that as a
// calibration problem: it decrypts a few sample windows with each plausible
// combination (key unwrapping x cipher mode x page size x start offset) and
// scores the result by how much valid *plaintext structure* appears - binlog
// TABLE_MAP events with real identifiers, and GCache BufferHeader signatures.
// Random bytes score ~0, the correct combination scores high, so the winner is
// unambiguous. The result is reported in --debug and can be pinned afterwards
// with --enc-scheme / --enc-page-size / --enc-base to skip the search.

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	keyringFile  = flag.String("keyring-file", "", "Path to the keyring component file (JSON) holding the GCache master key")
	masterKeyHex = flag.String("master-key", "", "Master key as hex (64 chars for AES-256), instead of reading a keyring")
	dumpPreamble = flag.Bool("dump-preamble", false, "Print the raw preamble (text + hexdump) and exit")
	noPrompt     = flag.Bool("no-prompt", false, "Never ask interactively for key material")

	vaultURL       = flag.String("vault-url", "", "HashiCorp Vault address (default $VAULT_ADDR)")
	vaultToken     = flag.String("vault-token", "", "Vault token (default $VAULT_TOKEN)")
	vaultTokenFile = flag.String("vault-token-file", "", "File containing the Vault token")
	vaultMount     = flag.String("vault-mount", "secret", "Vault KV mount holding the keyring secrets")
	vaultPath      = flag.String("vault-path", "", "Explicit Vault path to the master key (overrides --vault-mount)")
	vaultNamespace = flag.String("vault-namespace", "", "Vault namespace header, if any")
	vaultInsecure  = flag.Bool("vault-insecure", false, "Skip TLS verification when talking to Vault")

	encScheme   = flag.String("enc-scheme", "", "Pin the cipher layout instead of auto-detecting (ctr-file, ctr-page, ctr-page-lo, ctr-page-off, ctr-page-le, xts, cbc-page, cbc-page-zero, ecb)")
	encPageSize = flag.Int("enc-page-size", 0, "Pin the encryption page size in bytes (0 = auto-detect)")
	encBase     = flag.Int("enc-base", -1, "Pin the file offset where the encrypted region starts (-1 = auto-detect)")
	encProbe    = flag.Bool("enc-probe", false, "Analyze the encrypted file layout without any key, print findings and exit")
	fileKeyHex  = flag.String("file-key", "", "Use this file key directly (hex/base64), skipping master-key unwrapping")
	dumpDecrypted = flag.String("dump-decrypted", "", "After decrypting, write the plaintext image to this path (for offline inspection)")
)

func zeroTailStr(pr probeResult) string {
	if pr.ZeroTail == 0 {
		return "end of file"
	}
	return fmt.Sprintf("0x%x", pr.ZeroTail)
}

// Cipher layout candidates. All use the File Key with AES; they differ in mode
// and in how the IV/tweak is derived from the position in the file.
const (
	schemeCTRFile     = "ctr-file"     // one CTR stream over the region, counter = block index
	schemeCTRPage     = "ctr-page"     // CTR per page, IV = pageIndex big-endian in the HIGH half
	schemeCTRPageLo   = "ctr-page-lo"  // CTR per page, IV = pageIndex big-endian in the LOW half
	schemeCTRPageOff  = "ctr-page-off" // CTR per page, counter = byte offset of the page
	schemeCTRPageLE   = "ctr-page-le"  // CTR per page, IV = pageIndex little-endian, first 8 bytes
	schemeXTS         = "xts"          // AES-XTS, key split in half, sector = pageIndex
	schemeCBCPage     = "cbc-page"     // CBC per page, IV = pageIndex
	schemeCBCPageZero = "cbc-page-zero"
	schemeECB         = "ecb" // AES-ECB (position independent)
)

var allSchemes = []string{
	schemeCTRFile, schemeCTRPage, schemeCTRPageLo, schemeCTRPageOff, schemeCTRPageLE,
	schemeXTS, schemeCBCPage, schemeCBCPageZero, schemeECB,
}

// encInfo holds the encryption-related preamble fields.
type encInfo struct {
	Seen        bool   // the preamble carried encryption keys at all
	Encrypted   bool   // ... and says the file is encrypted
	Version     int    // enc_version / EncVersion
	MKID        string // enc_mk_id / MasterKey ID
	MKConstUUID string // enc_mk_const_id / MasterKeyConst UUID
	MKUUID      string // enc_mk_uuid / MasterKey UUID
	FKWrapped   []byte // enc_fk_id: the File Key, encrypted with the Master Key
	FKField     string // preamble key the wrapped File Key came from
	CRC         string
	Extra       map[string]string // every other enc-looking key, for --debug
}

// normKey lower-cases a preamble key and drops everything that is not a letter
// or digit, so "MasterKeyConst UUID" and "enc_mk_const_id" can be compared.
func normKey(k string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(k) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// note records one preamble key/value pair if it is encryption related.
func (e *encInfo) note(key, val string) {
	if e.Extra == nil {
		e.Extra = map[string]string{}
	}
	v := firstToken(val)
	switch normKey(key) {
	case "encversion", "encryptionversion":
		e.Seen = true
		e.Version, _ = strconv.Atoi(v)
	case "encencrypted", "encrypted":
		e.Seen = true
		switch strings.ToLower(v) {
		case "1", "yes", "on", "true":
			e.Encrypted = true
		}
	case "encmkid", "masterkeyid":
		e.Seen = true
		e.MKID = v
	case "encmkconstid", "masterkeyconstuuid", "masterkeyconstid":
		e.Seen = true
		e.MKConstUUID = v
	case "encmkuuid", "masterkeyuuid":
		e.Seen = true
		e.MKUUID = v
	case "enccrc", "encryptioncrc":
		e.CRC = v
	default:
		nk := normKey(key)
		if strings.Contains(nk, "filekey") || strings.Contains(nk, "fk") {
			if raw := decodeBlob(v); len(raw) > 0 {
				e.Seen = true
				e.FKWrapped = raw
				e.FKField = key
			}
		}
		if strings.HasPrefix(nk, "enc") || strings.Contains(nk, "masterkey") ||
			strings.Contains(nk, "filekey") {
			e.Extra[key] = val
		}
	}
}

// masterKeyID rebuilds the keyring entry name Galera uses for the master key.
func (e *encInfo) masterKeyID() string {
	if e.MKUUID == "" || e.MKConstUUID == "" || e.MKID == "" {
		return ""
	}
	return fmt.Sprintf("GaleraKey-%s@%s-%s", e.MKUUID, e.MKConstUUID, e.MKID)
}

// decodeBlob accepts base64 or hex and returns the bytes if the length looks
// like key material (128/256/384/512 bit).
func decodeBlob(s string) []byte {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// hex first: a 64-char hex key is also valid base64 and would otherwise be
	// decoded into 48 bytes of nonsense.
	if b, err := hex.DecodeString(s); err == nil && keyLenOK(len(b)) {
		return b
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && keyLenOK(len(b)) {
		return b
	}
	return nil
}

func keyLenOK(n int) bool { return n == 16 || n == 32 || n == 48 || n == 64 }

// ---------------------------------------------------------------------------
// Master key sources
// ---------------------------------------------------------------------------

type keyringElement struct {
	User     string `json:"user"`
	DataID   string `json:"data_id"`
	DataType string `json:"data_type"`
	Data     string `json:"data"`
}

type keyringDoc struct {
	Version  string           `json:"version"`
	Elements []keyringElement `json:"elements"`
}

// resolveMasterKey obtains the master key from whichever source the user
// configured, prompting interactively as a last resort.
func resolveMasterKey(e *encInfo) (masterKey, error) {
	want := e.masterKeyID()

	if *masterKeyHex != "" {
		k := decodeBlob(*masterKeyHex)
		if k == nil {
			return masterKey{}, fmt.Errorf("--master-key is not 16/32/64 bytes of hex or base64")
		}
		return masterKey{raw: k, text: strings.TrimSpace(*masterKeyHex), source: "--master-key"}, nil
	}
	if *keyringFile != "" {
		mk, err := loadKeyFromKeyringFile(*keyringFile, want)
		if err != nil {
			return masterKey{}, err
		}
		mk.source = fmt.Sprintf("%s (%s)", *keyringFile, mk.source)
		return mk, nil
	}
	if *vaultURL != "" || *vaultPath != "" || os.Getenv("VAULT_ADDR") != "" {
		return loadKeyFromVault(want)
	}
	if !*noPrompt && isTTY(os.Stdin) {
		return promptForKey(e)
	}
	return masterKey{}, fmt.Errorf("no master key given; use --keyring-file, --master-key or --vault-url%s",
		hintKeyID(want))
}

func hintKeyID(want string) string {
	if want == "" {
		return ""
	}
	return fmt.Sprintf(" (the keyring entry is data_id %q)", want)
}

func loadKeyFromKeyringFile(path, want string) (masterKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return masterKey{}, err
	}
	var doc keyringDoc
	if err := json.Unmarshal(bytes.TrimSpace(raw), &doc); err != nil {
		if bytes.Contains(raw[:minInt(len(raw), 64)], []byte("Keyring file version")) {
			return masterKey{}, fmt.Errorf("%s is the binary keyring_file *plugin* format, which this tool "+
				"cannot read; use a keyring component file (JSON) or pass --master-key <hex>", path)
		}
		return masterKey{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	var galera []keyringElement
	for _, el := range doc.Elements {
		if want != "" && el.DataID == want {
			return elementKey(el)
		}
		if strings.HasPrefix(el.DataID, "GaleraKey-") {
			galera = append(galera, el)
		}
	}
	if len(galera) == 0 {
		var ids []string
		for _, el := range doc.Elements {
			ids = append(ids, el.DataID)
		}
		if len(ids) > 8 {
			ids = append(ids[:8], "...")
		}
		return masterKey{}, fmt.Errorf("no GaleraKey-* entry in %s (found: %s)", path, strings.Join(ids, ", "))
	}
	// No exact match (rotated key, or the preamble did not carry all three
	// parts): fall back to the highest master-key sequence number present.
	sort.Slice(galera, func(i, j int) bool { return mkSeq(galera[i].DataID) < mkSeq(galera[j].DataID) })
	el := galera[len(galera)-1]
	if want != "" {
		fmt.Fprintf(os.Stderr, "%s preamble asks for %q, using %q from the keyring instead\n",
			warn("Note:"), want, el.DataID)
	}
	return elementKey(el)
}

func elementKey(el keyringElement) (masterKey, error) {
	k := decodeBlob(el.Data)
	if k == nil {
		return masterKey{}, fmt.Errorf("keyring entry %q holds no usable key material", el.DataID)
	}
	return masterKey{raw: k, text: strings.TrimSpace(el.Data), source: el.DataID}, nil
}

// mkSeq extracts the trailing "-<n>" master key sequence from a GaleraKey id.
func mkSeq(dataID string) int {
	if i := strings.LastIndexByte(dataID, '-'); i >= 0 {
		if n, err := strconv.Atoi(dataID[i+1:]); err == nil {
			return n
		}
	}
	return -1
}

func loadKeyFromVault(want string) (masterKey, error) {
	addr := *vaultURL
	if addr == "" {
		addr = os.Getenv("VAULT_ADDR")
	}
	if addr == "" {
		return masterKey{}, fmt.Errorf("no Vault address (--vault-url or $VAULT_ADDR)")
	}
	addr = strings.TrimRight(addr, "/")

	token := *vaultToken
	if token == "" && *vaultTokenFile != "" {
		b, err := os.ReadFile(*vaultTokenFile)
		if err != nil {
			return masterKey{}, err
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		return masterKey{}, fmt.Errorf("no Vault token (--vault-token, --vault-token-file or $VAULT_TOKEN)")
	}

	var paths []string
	if *vaultPath != "" {
		paths = []string{*vaultPath}
	} else {
		if want == "" {
			return masterKey{}, fmt.Errorf("preamble has no master key id; pass --vault-path explicitly")
		}
		m := strings.Trim(*vaultMount, "/")
		paths = []string{m + "/data/" + want, m + "/" + want}
	}

	client := &http.Client{Timeout: 15 * time.Second}
	if *vaultInsecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	var lastErr error
	for _, p := range paths {
		u := addr + "/v1/" + strings.TrimLeft(p, "/")
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("X-Vault-Token", token)
		if *vaultNamespace != "" {
			req.Header.Set("X-Vault-Namespace", *vaultNamespace)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
			continue
		}
		var v interface{}
		if err := json.Unmarshal(body, &v); err != nil {
			lastErr = fmt.Errorf("%s: %w", u, err)
			continue
		}
		if k, txt := findKeyMaterial(v); k != nil {
			return masterKey{raw: k, text: txt, source: u}, nil
		}
		lastErr = fmt.Errorf("%s: no key material found in the response", u)
	}
	return masterKey{}, lastErr
}

// findKeyMaterial walks a decoded Vault JSON response looking for a string that
// decodes to a plausible AES key. Keyring implementations wrap the value
// differently (data.data.value, data.value, sometimes "<type>:<len>:<key>"), so
// this stays deliberately generic.
func findKeyMaterial(v interface{}) ([]byte, string) {
	switch t := v.(type) {
	case string:
		if k := decodeBlob(t); k != nil {
			return k, t
		}
		if i := strings.LastIndexByte(t, ':'); i >= 0 {
			if k := decodeBlob(t[i+1:]); k != nil {
				return k, t[i+1:]
			}
		}
	case []interface{}:
		for _, el := range t {
			if k, txt := findKeyMaterial(el); k != nil {
				return k, txt
			}
		}
	case map[string]interface{}:
		for _, pref := range []string{"data", "value", "key", "material"} {
			if el, ok := t[pref]; ok {
				if k, txt := findKeyMaterial(el); k != nil {
					return k, txt
				}
			}
		}
		for _, el := range t {
			if k, txt := findKeyMaterial(el); k != nil {
				return k, txt
			}
		}
	}
	return nil, ""
}

func promptForKey(e *encInfo) (masterKey, error) {
	in := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%s\n", warn("This GCache file is encrypted."))
	if want := e.masterKeyID(); want != "" {
		fmt.Printf("%s %s\n", dim("Master key id:"), id(want))
	}
	fmt.Printf("%s\n", dim("Enter the path to the keyring component file, a 64-char hex master key,"))
	fmt.Printf("%s", dim("or \"vault\" to give Vault details: "))
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return masterKey{}, fmt.Errorf("no key given")
	}
	ans := strings.TrimSpace(line)
	switch {
	case ans == "":
		return masterKey{}, fmt.Errorf("no key given")
	case strings.EqualFold(ans, "vault"):
		if *vaultURL == "" {
			fmt.Printf("%s", dim("Vault URL: "))
			s, _ := in.ReadString('\n')
			*vaultURL = strings.TrimSpace(s)
		}
		if *vaultToken == "" && *vaultTokenFile == "" && os.Getenv("VAULT_TOKEN") == "" {
			fmt.Printf("%s", dim("Vault token: "))
			s, _ := in.ReadString('\n')
			*vaultToken = strings.TrimSpace(s)
		}
		if *vaultPath == "" {
			fmt.Printf("%s", dim("Vault path (blank = "+*vaultMount+"/<master key id>): "))
			s, _ := in.ReadString('\n')
			*vaultPath = strings.TrimSpace(s)
		}
		return loadKeyFromVault(e.masterKeyID())
	default:
		if k := decodeBlob(ans); k != nil {
			return masterKey{raw: k, text: ans, source: "typed master key"}, nil
		}
		mk, err := loadKeyFromKeyringFile(ans, e.masterKeyID())
		if err != nil {
			return masterKey{}, err
		}
		mk.source = fmt.Sprintf("%s (%s)", ans, mk.source)
		return mk, nil
	}
}

// ---------------------------------------------------------------------------
// File key unwrapping
// ---------------------------------------------------------------------------

// keyCand is a candidate key together with a label describing how it was
// derived, so --debug can report which derivation actually worked.
type keyCand struct {
	key []byte
	how string
}

// masterKey is the key material as it came out of the keyring, kept in both
// forms: the decoded bytes and the original text field.
type masterKey struct {
	raw    []byte
	text   string
	source string
}

// masterKeyCandidates covers the ways a master key can reach the provider.
// Galera hands the keyring string straight to OpenSSL as an AES key
// (EncMMap::set_key -> key.c_str()), so whether the server passes raw bytes or
// the hex text matters: with hex text OpenSSL silently uses only its first 32
// characters as the key.
func masterKeyCandidates(mk masterKey) []keyCand {
	var out []keyCand
	add := func(b []byte, how string) {
		switch {
		case len(b) >= 32:
			out = append(out, keyCand{b[:32], how})
		case len(b) == 16 || len(b) == 24:
			out = append(out, keyCand{b, how})
		}
	}
	add(mk.raw, "keyring bytes")
	if t := strings.TrimSpace(mk.text); t != "" {
		add([]byte(t), "keyring text as ASCII")
		if l := strings.ToLower(t); l != t {
			add([]byte(l), "keyring text lower-cased")
		}
		if u := strings.ToUpper(t); u != t {
			add([]byte(u), "keyring text upper-cased")
		}
	}
	if len(mk.raw) > 0 {
		h := sha256.Sum256(mk.raw)
		add(h[:], "sha256(keyring bytes)")
	}
	if mk.text != "" {
		h := sha256.Sum256([]byte(mk.text))
		add(h[:], "sha256(keyring text)")
	}
	return dedupCands(out)
}

// fileKeyCandidates unwraps the preamble's enc_fk_id with each master key
// candidate. gu::decrypt_key() (galerautils/src/gu_enc_utils.cpp) is AES-CTR
// with an all-zero IV and the master key used raw - and it asserts that both
// the master key and the wrapped key are exactly FILE_KEY_LENGTH (32) bytes,
// which also proves the provider hands over decoded bytes rather than hex text.
// The other modes are kept only as a safety net for older builds.
func fileKeyCandidates(mks []keyCand, wrapped []byte) []keyCand {
	var out []keyCand
	add := func(b []byte, how string) {
		switch {
		case len(b) >= 32:
			out = append(out, keyCand{b[:32], how})
		case len(b) == 16 || len(b) == 24:
			out = append(out, keyCand{b, how})
		}
	}
	for _, mk := range mks {
		blk, err := aes.NewCipher(mk.key)
		if err != nil || len(wrapped) < 16 || len(wrapped)%16 != 0 {
			continue
		}
		ctr := make([]byte, len(wrapped))
		cipher.NewCTR(blk, make([]byte, 16)).XORKeyStream(ctr, wrapped)
		add(ctr, "CTR unwrap (zero IV), "+mk.how) // what the sources do

		ecb := make([]byte, len(wrapped))
		for i := 0; i+16 <= len(wrapped); i += 16 {
			blk.Decrypt(ecb[i:i+16], wrapped[i:i+16])
		}
		add(ecb, "ECB unwrap, "+mk.how)

		cbc := make([]byte, len(wrapped))
		cipher.NewCBCDecrypter(blk, make([]byte, 16)).CryptBlocks(cbc, wrapped)
		add(cbc, "CBC unwrap (zero IV), "+mk.how)

		add(mk.key, "master key used directly, "+mk.how)
	}
	add(wrapped, "wrapped key used as-is")
	return dedupCands(out)
}

func dedupCands(in []keyCand) []keyCand {
	var out []keyCand
	seen := map[string]bool{}
	for _, k := range in {
		if seen[string(k.key)] {
			continue
		}
		seen[string(k.key)] = true
		out = append(out, k)
	}
	return out
}

// preambleBlobs harvests every base64/hex token in the preamble region that has
// the shape of key material, for builds whose preamble key names this tool does
// not know yet.
func preambleBlobs(data []byte) [][]byte {
	n := 8192
	if n > len(data) {
		n = len(data)
	}
	txt := data[:n]
	isTok := func(c byte) bool {
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '='
	}
	var out [][]byte
	for i := 0; i < len(txt); {
		if !isTok(txt[i]) {
			i++
			continue
		}
		j := i
		for j < len(txt) && isTok(txt[j]) {
			j++
		}
		if j-i >= 22 && j-i <= 200 {
			if b := decodeBlob(string(txt[i:j])); b != nil {
				out = append(out, b)
			}
		}
		i = j
	}
	return dedupKeys(out)
}

func dedupKeys(in [][]byte) [][]byte {
	var out [][]byte
	seen := map[string]bool{}
	for _, k := range in {
		s := string(k)
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------
// Page decryption
// ---------------------------------------------------------------------------

type encParams struct {
	scheme string
	page   int
	base   int // file offset the position counter is measured from
	plain  int // bytes at the start of the file that are NOT encrypted
	key    []byte
	keyHow string // how the file key was derived (for --debug)
}

func (p encParams) String() string {
	bits := len(p.key) * 8
	var layout string
	switch p.scheme {
	case schemeCTRFile, schemeECB:
		layout = fmt.Sprintf("AES-%d-%s, clear below 0x%x, counter from 0x%x",
			bits, p.scheme, p.plain, p.base)
	case schemeXTS:
		layout = fmt.Sprintf("AES-%d-xts, %d B pages, clear below 0x%x", bits/2, p.page, p.plain)
	default:
		layout = fmt.Sprintf("AES-%d-%s, %d B pages, clear below 0x%x, counter from 0x%x",
			bits, p.scheme, p.page, p.plain, p.base)
	}
	if p.keyHow != "" {
		layout += " [" + p.keyHow + "]"
	}
	return layout
}

// decryptInto decrypts src (ciphertext starting at absolute file offset absOff)
// into dst. absOff must sit on a page boundary relative to p.base.
func decryptInto(dst, src []byte, absOff int, p encParams) bool {
	if len(dst) != len(src) || len(src) == 0 {
		return false
	}
	rel := absOff - p.base
	if rel < 0 {
		return false
	}
	if p.scheme == schemeCTRFile {
		blk, err := aes.NewCipher(p.key)
		if err != nil || rel%16 != 0 {
			return false
		}
		iv := make([]byte, 16)
		binary.BigEndian.PutUint64(iv[8:], uint64(rel/16))
		cipher.NewCTR(blk, iv).XORKeyStream(dst, src)
		return true
	}
	return decryptPages(dst, src, rel, p)
}

func decryptPages(dst, src []byte, rel int, p encParams) bool {
	page := p.page
	if p.scheme == schemeECB {
		page = 1 << 20 // position independent; chunk size is arbitrary
		if rel%16 != 0 {
			return false
		}
	} else if page <= 0 || page%16 != 0 || rel%page != 0 {
		return false
	}

	blk, err := aes.NewCipher(p.key)
	if err != nil {
		return false
	}
	var blk2 cipher.Block
	if p.scheme == schemeXTS {
		half := len(p.key) / 2
		b1, e1 := aes.NewCipher(p.key[:half])
		b2, e2 := aes.NewCipher(p.key[half:])
		if e1 != nil || e2 != nil {
			return false
		}
		blk, blk2 = b1, b2
	}

	for o := 0; o < len(src); o += page {
		end := o + page
		if end > len(src) {
			end = len(src)
		}
		n := (end - o) - (end-o)%16
		if n == 0 {
			copy(dst[o:end], src[o:end])
			break
		}
		idx := uint64((rel + o) / page)
		switch p.scheme {
		case schemeCTRPage, schemeCTRPageLo, schemeCTRPageOff, schemeCTRPageLE:
			iv := make([]byte, 16)
			switch p.scheme {
			case schemeCTRPage:
				binary.BigEndian.PutUint64(iv[:8], idx)
			case schemeCTRPageLo:
				binary.BigEndian.PutUint64(iv[8:], idx)
			case schemeCTRPageOff:
				binary.BigEndian.PutUint64(iv[8:], uint64(rel+o))
			case schemeCTRPageLE:
				binary.LittleEndian.PutUint64(iv[:8], idx)
			}
			cipher.NewCTR(blk, iv).XORKeyStream(dst[o:o+n], src[o:o+n])
		case schemeCBCPage, schemeCBCPageZero:
			iv := make([]byte, 16)
			if p.scheme == schemeCBCPage {
				binary.BigEndian.PutUint64(iv[:8], idx)
			}
			cipher.NewCBCDecrypter(blk, iv).CryptBlocks(dst[o:o+n], src[o:o+n])
		case schemeECB:
			for i := 0; i+16 <= n; i += 16 {
				blk.Decrypt(dst[o+i:o+i+16], src[o+i:o+i+16])
			}
		case schemeXTS:
			copy(dst[o:o+n], src[o:o+n])
			xtsDecryptSector(blk, blk2, idx, dst[o:o+n])
		default:
			return false
		}
		if end > o+n { // trailing partial block: leave as is
			copy(dst[o+n:end], src[o+n:end])
		}
	}
	return true
}

// xtsDecryptSector decrypts one XTS sector in place (buf must be a multiple of
// the 16-byte block size; GCache pages always are).
func xtsDecryptSector(dataKey, tweakKey cipher.Block, sector uint64, buf []byte) {
	var tweak [16]byte
	binary.LittleEndian.PutUint64(tweak[:8], sector)
	tweakKey.Encrypt(tweak[:], tweak[:])
	var x [16]byte
	for i := 0; i+16 <= len(buf); i += 16 {
		for j := 0; j < 16; j++ {
			x[j] = buf[i+j] ^ tweak[j]
		}
		dataKey.Decrypt(x[:], x[:])
		for j := 0; j < 16; j++ {
			buf[i+j] = x[j] ^ tweak[j]
		}
		// tweak *= alpha in GF(2^128), LSB-first convention
		carry := byte(0)
		for j := 0; j < 16; j++ {
			next := tweak[j] >> 7
			tweak[j] = tweak[j]<<1 | carry
			carry = next
		}
		if carry != 0 {
			tweak[0] ^= 0x87
		}
	}
}

// ---------------------------------------------------------------------------
// Structural probe (no key needed)
// ---------------------------------------------------------------------------
//
// The cipher layout leaves fingerprints in the ciphertext that can be read
// without any key at all:
//
//   - The plaintext preamble ends where the bytes stop looking like text or
//     zeros and start looking random. That offset is the base of the encrypted
//     region.
//   - A pre-allocated RingBuffer that has not wrapped yet still has literal
//     zero bytes in the never-written tail, which tells us which part of the
//     file actually holds write-sets (and therefore where to sample).
//   - Regions whose plaintext is all zeros encrypt to the bare keystream. If
//     the keystream restarts per page, the ciphertext repeats itself with a
//     period equal to the page size - so identical 16-byte blocks and the
//     distances between them reveal the page size, and a single dominant
//     repeated block betrays ECB or a fixed IV.

type probeResult struct {
	TextEnd   int   // last offset that still looked like preamble text
	CipherAt  int   // first offset that looks encrypted
	ZeroTail  int   // start of the trailing run of literal zero bytes (0 = none)
	Period    int   // repetition period of the ciphertext (0 = none found)
	PeriodHit int   // how many block pairs agreed on that period
	DupBlocks int   // duplicate 16-byte blocks in the sample
	TopBlock  int   // occurrences of the single most repeated block
	Written   []int // offsets that look like written ciphertext
}

const probeBlk = 512

// blockKind classifies a chunk as 0 = all zeros, 1 = text (possibly NUL
// padded, which is how the preamble is stored), 2 = random/encrypted.
func blockKind(b []byte) int {
	zeros, printable := 0, 0
	for _, c := range b {
		switch {
		case c == 0:
			zeros++
		case (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t':
			printable++
		}
	}
	if zeros == len(b) {
		return 0
	}
	// The preamble is written into a NUL-filled buffer, so judge only the
	// non-zero part: a short text line followed by padding is still text.
	if nz := len(b) - zeros; printable >= 8 && printable*10 >= nz*9 {
		return 1
	}
	return 2
}

func probe(data []byte) probeResult {
	r := probeResult{}
	n := len(data)

	// 1. Where does the plaintext preamble end?
	limit := 1 << 20
	if limit > n {
		limit = n
	}
	i := 0
	for ; i+probeBlk <= limit; i += probeBlk {
		k := blockKind(data[i : i+probeBlk])
		if k == 2 {
			break
		}
		if k == 1 {
			r.TextEnd = i + probeBlk
		}
	}
	r.CipherAt = i

	// 2. Trailing run of literal zeros = never-written part of the ring buffer.
	z := n
	for z-probeBlk >= r.CipherAt {
		if blockKind(data[z-probeBlk:z]) != 0 {
			break
		}
		z -= probeBlk
	}
	if z < n {
		r.ZeroTail = z
	}

	// 3. Repetition analysis over a sample of the encrypted region.
	end := n
	if r.ZeroTail > 0 {
		end = r.ZeroTail
	}
	sampleEnd := r.CipherAt + (4 << 20) // bounded: this pass builds a block index
	if sampleEnd > end {
		sampleEnd = end
	}
	first := map[string]int{}
	dist := map[int]int{}
	top := 0
	for o := r.CipherAt; o+16 <= sampleEnd; o += 16 {
		k := string(data[o : o+16])
		if prev, ok := first[k]; ok {
			r.DupBlocks++
			d := o - prev
			dist[d]++
			if dist[d] > top {
				top = dist[d]
			}
			continue
		}
		first[k] = o
	}
	bestD, bestC := 0, 0
	for d, c := range dist {
		if c > bestC || (c == bestC && d < bestD) {
			bestD, bestC = d, c
		}
	}
	if bestC >= 8 {
		r.Period, r.PeriodHit = bestD, bestC
	}
	r.TopBlock = top

	// 4. Sample offsets that look like written ciphertext.
	r.Written = writtenWindows(data, r, 6)
	return r
}

// writtenWindows picks offsets to sample. A ring buffer that has not wrapped
// keeps its write-sets right after the preamble, so the early offsets matter
// most; the even spread afterwards covers a cache that has wrapped.
func writtenWindows(data []byte, r probeResult, want int) []int {
	lo := r.CipherAt
	if lo < 4096 {
		lo = 4096 // PREAMBLE_LEN: never sample the clear preamble
	}
	hi := len(data)
	if r.ZeroTail > lo {
		hi = r.ZeroTail
	}
	if hi-lo <= 0 {
		return nil
	}
	seen := map[int]bool{}
	var out []int
	add := func(o int) {
		if o >= lo && o+4096 < hi && !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	for _, o := range []int{lo, lo + (64 << 10), lo + (1 << 20), lo + (8 << 20)} {
		add(o)
	}
	step := (hi - lo) / want
	if step < 4096 {
		step = 4096
	}
	for o := lo; o < hi && len(out) < want*2; o += step {
		add(o)
	}
	return out
}

func printProbe(path string, data []byte, r probeResult) {
	fmt.Printf("%s\n", hi("=== encrypted layout probe ==="))
	fmt.Printf("%s %s\n", dim("File:              "), path)
	fmt.Printf("%s %d bytes\n", dim("Size:              "), len(data))
	fmt.Printf("%s 0x%x (%d)\n", dim("Preamble text ends:"), r.TextEnd, r.TextEnd)
	fmt.Printf("%s 0x%x (%d)  %s\n", dim("Ciphertext starts: "), r.CipherAt, r.CipherAt,
		dim("<- candidate --enc-base"))
	if r.ZeroTail > 0 {
		fmt.Printf("%s 0x%x (%d)  %s\n", dim("Literal zeros from:"), r.ZeroTail, r.ZeroTail,
			dim(fmt.Sprintf("(%.1f MB of the file was ever written)",
				float64(r.ZeroTail-r.CipherAt)/(1024*1024))))
	} else {
		fmt.Printf("%s %s\n", dim("Literal zeros:     "), dim("none - the whole file looks written/encrypted"))
	}
	fmt.Printf("%s %d duplicate 16-byte blocks", dim("Block repeats:     "), r.DupBlocks)
	if r.TopBlock > 0 {
		fmt.Printf(", most common distance seen %d times", r.TopBlock)
	}
	fmt.Printf("\n")
	if r.Period > 0 {
		fmt.Printf("%s %d bytes  %s\n", dim("Keystream period:  "), r.Period,
			dim(fmt.Sprintf("(%d agreeing pairs) <- candidate --enc-page-size", r.PeriodHit)))
	} else {
		fmt.Printf("%s %s\n", dim("Keystream period:  "),
			dim("none found (continuous stream, XTS, or no all-zero plaintext sampled)"))
	}
	if len(r.Written) > 0 {
		var parts []string
		for _, o := range r.Written {
			parts = append(parts, fmt.Sprintf("0x%x", o))
		}
		fmt.Printf("%s %s\n", dim("Sample windows:    "), strings.Join(parts, " "))
	}

	// Bytes around the plaintext/ciphertext boundary, which show the padding
	// style and the exact first encrypted byte.
	from := r.TextEnd - 64
	if from < 0 {
		from = 0
	}
	fmt.Printf("\n%s\n", hi("--- bytes around the preamble/ciphertext boundary ---"))
	hexdumpRange(data, from, r.CipherAt+128)
	fmt.Printf("\n%s\n", hi("--- first 128 bytes of the encrypted region ---"))
	hexdumpRange(data, r.CipherAt, r.CipherAt+128)
}

func hexdumpRange(data []byte, from, to int) {
	if from < 0 {
		from = 0
	}
	if to > len(data) {
		to = len(data)
	}
	for p := from; p < to; p += 16 {
		e := p + 16
		if e > to {
			e = to
		}
		fmt.Printf("%08x: ", p)
		for k := p; k < e; k++ {
			fmt.Printf("%02x ", data[k])
		}
		for k := e; k < p+16; k++ {
			fmt.Printf("   ")
		}
		fmt.Printf(" |")
		for k := p; k < e; k++ {
			c := data[k]
			if c < 0x20 || c >= 0x7f {
				c = '.'
			}
			fmt.Printf("%c", c)
		}
		fmt.Printf("|\n")
	}
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

// plaintextScore measures how much valid GCache/binlog structure a buffer
// contains: TABLE_MAP events whose db/table names are real identifiers, and
// GCache BufferHeader signatures. Ciphertext (or a wrong key) scores ~0.
func plaintextScore(buf []byte) int {
	score := 0
	n := len(buf)

	// Strongest signal of all: the pre-allocated part of the ring buffer holds
	// encrypted zeros, so the correct key turns it back into zeros. A wrong key
	// yields keystream, which is never zeros. This works even where the cache
	// holds no write-sets yet, which structure-based scoring cannot.
	zeros := 0
	for _, c := range buf {
		if c == 0 {
			zeros++
		}
	}
	if n > 0 && zeros*4 >= n*3 {
		score += 100
	}
	for p := 0; p+headerLen < n; p++ {
		if buf[p+4] != evTableMap {
			continue
		}
		t, size, ok := readEvent(buf, p)
		if !ok || t != evTableMap {
			continue
		}
		if _, mok := parseTableMap(buf, p, size); mok {
			score += 10
		}
	}
	for h := 0; h+bhSize <= n; h++ {
		if buf[h+22] != bhInRB || buf[h+23] > 4 {
			continue
		}
		if binary.LittleEndian.Uint16(buf[h+20:h+22]) > bhFlagMax {
			continue
		}
		sz := int(binary.LittleEndian.Uint32(buf[h+16 : h+20]))
		if sz < bhSize || sz > 1<<28 {
			continue
		}
		score++
	}
	return score
}

const (
	fastWin   = 64 << 10  // sample size for the wide first pass
	fastWins  = 4         // windows per trial in the first pass
	fullWin   = 256 << 10 // sample size when re-scoring the shortlist
	fullWins  = 4
	minHit    = 4 // minimum score to accept a layout at all
	shortlist = 10
)

type calibHit struct {
	params encParams
	score  int
}

// candidateBases returns the offsets to try for the start of the encrypted
// region, best guess (from the probe) first.
func candidateBases(pr probeResult) []int {
	if *encBase >= 0 {
		return []int{*encBase}
	}
	seen := map[int]bool{}
	var out []int
	add := func(v int) {
		if v >= 0 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if pr.CipherAt > 0 {
		add(pr.CipherAt)
		add(pr.CipherAt &^ 4095)
	}
	for _, v := range []int{0, 4096, 8192, 1024, 2048, 16384, 32768, 65536} {
		add(v)
	}
	return out
}

func candidatePages(pr probeResult) []int {
	if *encPageSize > 0 {
		return []int{*encPageSize}
	}
	seen := map[int]bool{}
	var out []int
	add := func(v int) {
		if v >= 512 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if pr.Period > 0 && pr.Period%512 == 0 {
		add(pr.Period)
	}
	for _, v := range []int{32768, 4096, 8192, 16384, 65536, 131072, 262144} {
		add(v)
	}
	return out
}

// knownLayout is the scheme Percona's provider uses, now confirmed down to the
// counter bytes across three source files:
//   - enc_stream_cipher.cpp: AES-256-CTR. The 16-byte IV is open()'s IV (all
//     zeros here) in bytes 0..7, and counter = streamOffset/16 stored
//     big-endian in bytes 8..15. So keystream position == absolute file offset.
//   - gu_enc_mmap.cpp: decrypt() calls set_stream_offset(page_start_offset +
//     unencrypted_size), an absolute file offset, and the first
//     encryption_start_offset_ (= PREAMBLE_LEN) bytes are memcpy'd in clear
//     while still consuming their stream positions.
//   - gu_enc_utils.cpp: the file key itself is unwrapped with the same cipher,
//     zero IV, master key raw.
// Hence: one continuous AES-256-CTR stream, counter = byteOffset/16 big-endian
// in the low 8 bytes of a zero IV, clear below PREAMBLE_LEN.
func knownLayout(key keyCand, plain int) encParams {
	return encParams{
		scheme: schemeCTRFile,
		page:   32768,
		base:   0, // counter origin = start of file
		plain:  plain,
		key:    key.key,
		keyHow: key.how,
	}
}

// calibrate first tries the layout documented by the provider sources with
// every file-key derivation, and only falls back to the wider (cipher x page
// size x offset) search if none of them yields plaintext - which would mean
// this build differs from the sources we have.
func calibrate(data []byte, keys []keyCand, pr probeResult) (encParams, []calibHit, bool) {
	plain := pr.CipherAt
	if plain <= 0 {
		plain = 4096 // PREAMBLE_LEN
	}
	wins := pr.Written
	if len(wins) == 0 {
		wins = evenWindows(data, pr)
	}

	pinned := *encScheme != "" || *encBase >= 0 || *encPageSize > 0
	var hits []calibHit
	if !pinned {
		for _, k := range keys {
			p := knownLayout(k, plain)
			if sc := trialScore(data, p, wins, fastWins, fastWin); sc > 0 {
				hits = append(hits, calibHit{p, sc})
			}
		}
	}
	if len(hits) == 0 {
		hits = wideSearch(data, keys, pr, plain, wins)
	}
	sortHits(hits)
	if len(hits) == 0 {
		return encParams{}, nil, false
	}
	if len(hits) > shortlist {
		hits = hits[:shortlist]
	}
	for i := range hits {
		hits[i].score = trialScore(data, hits[i].params, wins, fullWins, fullWin)
	}
	sortHits(hits)
	return hits[0].params, hits, hits[0].score >= minHit
}

// wideSearch is the fallback: every cipher mode, page size and counter origin.
func wideSearch(data []byte, keys []keyCand, pr probeResult, plain int, wins []int) []calibHit {
	bases := candidateBases(pr)
	pages := candidatePages(pr)
	schemes := allSchemes
	if *encScheme != "" {
		schemes = []string{*encScheme}
	}
	var hits []calibHit
	for _, k := range keys {
		for _, base := range bases {
			if base >= len(data) {
				continue
			}
			for _, sch := range schemes {
				pg := pages
				if sch == schemeCTRFile || sch == schemeECB {
					pg = pages[:1] // page size is irrelevant for these
				}
				for _, page := range pg {
					p := encParams{scheme: sch, page: page, base: base, plain: plain,
						key: k.key, keyHow: k.how}
					if sc := trialScore(data, p, wins, fastWins, fastWin); sc > 0 {
						hits = append(hits, calibHit{p, sc})
					}
				}
			}
		}
	}
	return hits
}

func evenWindows(data []byte, pr probeResult) []int {
	lo := pr.CipherAt
	if lo >= len(data) {
		lo = 0
	}
	span := len(data) - lo
	var out []int
	for i := 0; i < 4; i++ {
		out = append(out, lo+span/4*i)
	}
	return out
}

func sortHits(h []calibHit) {
	sort.Slice(h, func(i, j int) bool { return h[i].score > h[j].score })
}

// trialScore decrypts a few sample windows with one candidate layout and
// scores the resulting plaintext.
func trialScore(data []byte, p encParams, wins []int, nwin, win int) int {
	align := p.page
	if align <= 0 || p.scheme == schemeCTRFile || p.scheme == schemeECB {
		align = 16
	}
	buf := make([]byte, win)
	total, used := 0, 0
	for _, w := range wins {
		if used >= nwin {
			break
		}
		if w < p.plain {
			w = p.plain
		}
		if w < p.base {
			continue
		}
		rel := w - p.base
		rel -= rel % align
		off := p.base + rel
		n := win
		if off+n > len(data) {
			n = len(data) - off
		}
		n -= n % 16
		if n <= 0 {
			continue
		}
		if !decryptInto(buf[:n], data[off:off+n], off, p) {
			return 0
		}
		total += plaintextScore(buf[:n])
		used++
	}
	return total
}

func decryptAll(data []byte, p encParams) []byte {
	if p.plain < 0 || p.plain >= len(data) {
		return nil
	}
	out := make([]byte, len(data))
	copy(out[:p.plain], data[:p.plain]) // preamble stays in clear
	if !decryptInto(out[p.plain:], data[p.plain:], p.plain, p) {
		return nil
	}
	return out
}

// ---------------------------------------------------------------------------
// Entry points used by main.go
// ---------------------------------------------------------------------------

// maybeDecrypt returns the plaintext image of an encrypted cache file, or the
// original bytes (with a note on the summary) when it cannot be decrypted.
func maybeDecrypt(data []byte, s *summary) []byte {
	e := &s.Enc
	if !e.Encrypted {
		return data
	}

	mk, err := resolveMasterKey(e)
	if err != nil {
		s.EncNote = err.Error()
		fmt.Fprintf(os.Stderr, "%s %v\n", warn("Encrypted GCache:"), err)
		return data
	}
	s.EncKeySource = mk.source

	// The wrapped file key normally comes from enc_fk_id. If this build names
	// it something we don't recognise, fall back to every key-shaped token in
	// the preamble - calibration will reject the wrong ones.
	wrapped := [][]byte{}
	if len(e.FKWrapped) > 0 {
		wrapped = append(wrapped, e.FKWrapped)
	} else {
		wrapped = preambleBlobs(data)
		if len(wrapped) == 0 {
			s.EncNote = "no wrapped file key found in the preamble; re-run with --dump-preamble"
			fmt.Fprintf(os.Stderr, "%s %s\n", warn("Encrypted GCache:"), s.EncNote)
			return data
		}
		if *debug {
			fmt.Fprintf(os.Stderr, "%s no known file-key field; trying %d key-shaped preamble token(s)\n",
				dim("enc calibration:"), len(wrapped))
		}
	}

	var keys []keyCand
	if *fileKeyHex != "" { // explicit file key wins over anything derived
		if k := decodeBlob(*fileKeyHex); k != nil {
			keys = []keyCand{{k, "--file-key"}}
		}
	}
	if len(keys) == 0 {
		mks := masterKeyCandidates(mk)
		for _, w := range wrapped {
			keys = append(keys, fileKeyCandidates(mks, w)...)
		}
		keys = dedupCands(keys)
		if len(keys) > 48 { // keep the search bounded
			keys = keys[:48]
		}
	}

	pr := probe(data)
	if *debug {
		fmt.Fprintf(os.Stderr, "%s ciphertext at 0x%x, written up to %s, keystream period %d\n",
			dim("enc probe:"), pr.CipherAt, zeroTailStr(pr), pr.Period)
	}
	p, hits, ok := calibrate(data, keys, pr)
	if *debug {
		fmt.Fprintf(os.Stderr, "%s %d file-key candidate(s), %d layout(s) scored above zero\n",
			dim("enc calibration:"), len(keys), len(hits))
		for i, h := range hits {
			if i >= 5 {
				break
			}
			fmt.Fprintf(os.Stderr, "  %s  score %d\n", dim(h.params.String()), h.score)
		}
	}
	if !ok {
		s.EncNote = "master key loaded, but no file-key derivation produced readable write-sets " +
			"(run with --debug for the scores; --file-key <hex> bypasses the unwrapping)"
		fmt.Fprintf(os.Stderr, "%s %s\n", warn("Encrypted GCache:"), s.EncNote)
		return data
	}
	out := decryptAll(data, p)
	if out == nil {
		s.EncNote = "decryption of the full file failed after calibration"
		return data
	}
	s.Decrypted = true
	s.EncScheme = p.String()
	detectEmptyRB(out, s) // cheap; sets s.EncEmptyRB
	if *debug {
		postDecryptDiag(out, s)
	}
	if *dumpDecrypted != "" {
		if err := os.WriteFile(*dumpDecrypted, out, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "%s could not write %s: %v\n", warn("dump-decrypted:"), *dumpDecrypted, err)
		} else {
			fmt.Fprintf(os.Stderr, "%s wrote decrypted image to %s\n", dim("dump-decrypted:"), *dumpDecrypted)
		}
	}
	return out
}


// detectEmptyRB reports whether the decrypted ring buffer holds any write-sets.
// An empty or cleanly-reset buffer decrypts to: the clear preamble, a small
// header_ array right after PREAMBLE_LEN, then nothing but zeros from start_ on.
// If every non-zero byte sits within ~4 KB of the preamble and the rest is all
// zeros, there are no persisted write-sets - which is normal, not an error.
func detectEmptyRB(data []byte, s *summary) {
	const preambleLen = 0x400
	const headerZone = preambleLen + 4096
	if headerZone >= len(data) {
		return
	}
	for i := headerZone; i < len(data); i++ {
		if data[i] != 0 {
			return // real data past the header area -> not empty
		}
	}
	// Everything past the header area is zero. Confirm something was decrypted
	// (a non-zero header) so we don't mislabel a totally blank file.
	for i := preambleLen; i < headerZone; i++ {
		if data[i] != 0 {
			s.EncEmptyRB = true
			return
		}
	}
}

// postDecryptDiag prints, under --debug, what the decrypted ring buffer looks
// like right where the first write-set should be (start_ = preamble_ +
// PREAMBLE_LEN + HEADER_LEN*8). It reports the balance of zero / text / random
// bytes and hunts for the first plausible binlog event or BufferHeader, which
// distinguishes "decrypted fine but the cache is empty" from "decryption is
// still wrong" from "framing is off".
func postDecryptDiag(data []byte, s *summary) {
	const preambleLen = 0x400
	fmt.Fprintf(os.Stderr, "%s\n", dim("enc post-decrypt diagnostics:"))

	// Byte-class census of the first 1 MB after the preamble.
	lo := preambleLen
	hi := lo + (1 << 20)
	if hi > len(data) {
		hi = len(data)
	}
	var z, t, r int
	for i := lo; i < hi; i++ {
		c := data[i]
		switch {
		case c == 0:
			z++
		case (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t':
			t++
		default:
			r++
		}
	}
	tot := hi - lo
	fmt.Fprintf(os.Stderr, "  %s zero %.0f%%, text %.0f%%, other %.0f%% (of %d KB after preamble)\n",
		dim("byte census:"),
		100*float64(z)/float64(tot), 100*float64(t)/float64(tot),
		100*float64(r)/float64(tot), tot/1024)
	if z*100 >= tot*99 {
		fmt.Fprintf(os.Stderr, "  %s\n", warn("the decrypted ring buffer is essentially all zeros -> the cache holds no write-sets"))
	}

	// Find the first non-zero region and hexdump it - that's where data, if
	// any, begins.
	firstNZ := -1
	for i := preambleLen; i < len(data); i++ {
		if data[i] != 0 {
			firstNZ = i
			break
		}
	}
	if firstNZ < 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", dim("no non-zero byte anywhere after the preamble"))
		return
	}
	fmt.Fprintf(os.Stderr, "  %s first non-zero byte at 0x%x (preamble+%d)\n",
		dim("data start:"), firstNZ, firstNZ-preambleLen)

	// Scan the WHOLE decrypted file for the first BufferHeader or TABLE_MAP,
	// and measure the total non-zero extent, so we can locate where the
	// ~150 KB of write-sets actually sit in the 128 MB buffer.
	var nonZero, firstData, lastData int
	for i := preambleLen; i < len(data); i++ {
		if data[i] != 0 {
			nonZero++
			if firstData == 0 {
				firstData = i
			}
			lastData = i
		}
	}
	fmt.Fprintf(os.Stderr, "  %s %d non-zero bytes total, spanning 0x%x..0x%x (%.1f KB)\n",
		dim("data extent:"), nonZero, firstData, lastData,
		float64(lastData-firstData)/1024)
	if s.EncEmptyRB {
		fmt.Fprintf(os.Stderr, "  %s only the header area after the preamble is non-zero; "+
			"the ring buffer itself is empty\n", good("empty RB:"))
	}

	foundBH, foundTM := -1, -1
	// Start past the header_ array (start_ = preamble + PREAMBLE_LEN +
	// HEADER_LEN int64s). A stray 24-byte window inside that header can pass the
	// loose BufferHeader signature test by chance (as at 0x4fe), so skip it; the
	// real scanner never anchors there because it also requires ring-buffer
	// chaining.
	searchFrom := preambleLen + 256 // 256 = HEADER_LEN(32) * 8, the header_ array
	if searchFrom < firstNZ {
		searchFrom = firstNZ
	}
	for p := searchFrom; p+bhSize <= len(data) && (foundBH < 0 || foundTM < 0); p++ {
		if data[p] == 0 && data[p+1] == 0 && data[p+2] == 0 && data[p+3] == 0 &&
			data[p+4] == 0 && data[p+5] == 0 && data[p+6] == 0 && data[p+7] == 0 {
			continue // cheap skip over zero runs
		}
		if foundBH < 0 && data[p+22] == bhInRB && data[p+23] <= 4 {
			if binary.LittleEndian.Uint16(data[p+20:p+22]) <= bhFlagMax {
				sz := int(binary.LittleEndian.Uint32(data[p+16 : p+20]))
				if sz >= bhSize && p+sz <= len(data) {
					foundBH = p
				}
			}
		}
		if foundTM < 0 && data[p+4] == evTableMap {
			if _, sz, ok := readEvent(data, p); ok {
				if _, mok := parseTableMap(data, p, sz); mok {
					foundTM = p
				}
			}
		}
	}
	if foundBH >= 0 {
		sz := int(binary.LittleEndian.Uint32(data[foundBH+16 : foundBH+20]))
		seq := int64(binary.LittleEndian.Uint64(data[foundBH : foundBH+8]))
		fmt.Fprintf(os.Stderr, "  %s BufferHeader at 0x%x (size=%d, seqno_g=%d)\n",
			good("found:"), foundBH, sz, seq)
	} else {
		fmt.Fprintf(os.Stderr, "  %s no BufferHeader signature anywhere in the file\n", warn("miss:"))
	}
	if foundTM >= 0 {
		if name, ok := parseTableMap(data, foundTM, func() int { _, sz, _ := readEvent(data, foundTM); return sz }()); ok {
			fmt.Fprintf(os.Stderr, "  %s TABLE_MAP at 0x%x for %s\n", good("found:"), foundTM, id(name))
		}
	} else {
		fmt.Fprintf(os.Stderr, "  %s no binlog TABLE_MAP anywhere in the file\n", warn("miss:"))
	}

	// Always show the first 128 bytes of data so the layout is visible.
	fmt.Fprintf(os.Stderr, "  %s\n", dim("first 128 bytes of decrypted data:"))
	hexdumpRangeStderr(data, firstNZ, firstNZ+128)
}

func hexdumpRangeStderr(data []byte, from, to int) {
	if to > len(data) {
		to = len(data)
	}
	for p := from; p < to; p += 16 {
		e := p + 16
		if e > to {
			e = to
		}
		fmt.Fprintf(os.Stderr, "    %08x: ", p)
		for k := p; k < e; k++ {
			fmt.Fprintf(os.Stderr, "%02x ", data[k])
		}
		fmt.Fprintf(os.Stderr, " |")
		for k := p; k < e; k++ {
			c := data[k]
			if c < 0x20 || c >= 0x7f {
				c = '.'
			}
			fmt.Fprintf(os.Stderr, "%c", c)
		}
		fmt.Fprintf(os.Stderr, "|\n")
	}
}

// printEncryption adds the encryption block to the header summary.
func printEncryption(s *summary) {
	if !s.Enc.Seen {
		return
	}
	if !s.Enc.Encrypted {
		fmt.Printf("%s %s\n", dim("Encrypted:"), good("no"))
		return
	}
	state := bad("yes — NOT decrypted")
	if s.Decrypted {
		state = good("yes — decrypted")
		if s.EncEmptyRB {
			state = good("yes — decrypted (ring buffer empty)")
		}
	}
	fmt.Printf("%s %s   %s\n", dim("Encrypted:"), state,
		dim(fmt.Sprintf("(enc version %d)", s.Enc.Version)))
	if kid := s.Enc.masterKeyID(); kid != "" {
		fmt.Printf("%s %s\n", dim("Master key:"), id(kid))
	}
	if s.EncKeySource != "" {
		fmt.Printf("%s %s\n", dim("Key source:"), dim(s.EncKeySource))
	}
	if s.Decrypted {
		fmt.Printf("%s %s\n", dim("Cipher:   "), id(s.EncScheme))
		fmt.Printf("%s %s\n", dim("Freshness:"),
			warn("on a live node the encrypted file lags the in-memory cache "+
				"(write-back page cache; flushed on eviction/shutdown)"))
	} else if s.EncNote != "" {
		fmt.Printf("%s %s\n", dim("Note:     "), warn(s.EncNote))
	}
}

// printEncDebug dumps every encryption-related preamble key (--debug).
func printEncDebug(s *summary) {
	if !s.Enc.Seen || len(s.Enc.Extra) == 0 {
		return
	}
	fmt.Printf("%s\n", hi("Encryption preamble keys:"))
	var ks []string
	for k := range s.Enc.Extra {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Printf("  %s %s\n", dim(k+":"), s.Enc.Extra[k])
	}
	if len(s.Enc.FKWrapped) > 0 {
		fmt.Printf("  %s %s\n", dim("wrapped file key:"),
			dim(fmt.Sprintf("%d bytes from %q", len(s.Enc.FKWrapped), s.Enc.FKField)))
	}
}

// dumpPreambleText prints the readable preamble plus a hexdump of the first
// bytes of the file - useful when a build stores encryption metadata under key
// names this tool does not know yet.
func dumpPreambleText(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return err
	}
	buf = buf[:n]

	fmt.Printf("%s\n", hi("--- preamble (text lines) ---"))
	for _, line := range strings.Split(string(buf), "\n") {
		line = printablePrefix(strings.TrimRight(line, "\r"))
		if strings.TrimSpace(line) == "" || !strings.Contains(line, ":") {
			continue
		}
		fmt.Println(line)
	}
	fmt.Printf("\n%s\n", hi("--- first 512 bytes ---"))
	end := 512
	if end > len(buf) {
		end = len(buf)
	}
	for p := 0; p < end; p += 16 {
		e := p + 16
		if e > end {
			e = end
		}
		fmt.Printf("%08x: ", p)
		for k := p; k < e; k++ {
			fmt.Printf("%02x ", buf[k])
		}
		fmt.Printf(" |")
		for k := p; k < e; k++ {
			c := buf[k]
			if c < 0x20 || c >= 0x7f {
				c = '.'
			}
			fmt.Printf("%c", c)
		}
		fmt.Printf("|\n")
	}
	return nil
}

// printablePrefix returns the leading run of printable ASCII, so a preamble
// line that runs into NUL padding still shows its text part.
func printablePrefix(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return s[:i]
		}
	}
	return s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
