package query

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	xorfilter "github.com/FastFilter/xorfilter"

	"github.com/gaetan-gg/cert-hunter/internal/formats"
)

// CertRecord holds the information stored for one certificate.
type CertRecord struct {
	FingerprintSHA1 [20]byte
	NotBefore       time.Time
	NotAfter        time.Time
	CN              string
}

// DB is a read-only handle to a cert-hunter index directory.
// Call Close when done.
type DB struct {
	filters   [formats.NumShards]*xorfilter.BinaryFuse8
	indexData []byte
	certsData []byte
	indexFile *os.File
	certsFile *os.File
	nSPKIs    int64
}

// Open opens an index directory produced by the build command.
func Open(dir string) (*DB, error) {
	db := &DB{}

	if err := db.loadFilters(filepath.Join(dir, "filter.bin")); err != nil {
		return nil, fmt.Errorf("loading filter: %w", err)
	}

	var err error
	db.indexData, db.indexFile, err = mmapFile(filepath.Join(dir, "index.bin"))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("mmap index: %w", err)
	}
	db.nSPKIs = int64(len(db.indexData)) / formats.IndexEntrySize

	db.certsData, db.certsFile, err = mmapFile(filepath.Join(dir, "certs.bin"))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("mmap certs: %w", err)
	}

	return db, nil
}

// Close releases mmap'd memory and file descriptors.
func (db *DB) Close() {
	if db.indexData != nil {
		syscall.Munmap(db.indexData)
		db.indexData = nil
	}
	if db.indexFile != nil {
		db.indexFile.Close()
		db.indexFile = nil
	}
	if db.certsData != nil {
		syscall.Munmap(db.certsData)
		db.certsData = nil
	}
	if db.certsFile != nil {
		db.certsFile.Close()
		db.certsFile = nil
	}
}

// Lookup looks up a single SPKI.
// spki may be a 20-byte SHA-1 hash or raw SubjectPublicKeyInfo DER bytes.
func (db *DB) Lookup(spki []byte) ([]CertRecord, error) {
	sha1Hash := normalizeSPKI(spki)
	if !db.filterCheck(sha1Hash) {
		return nil, nil
	}
	offset, count, ok := db.binarySearch(sha1Hash)
	if !ok {
		return nil, nil
	}
	return db.readCerts(offset, count)
}

// LookupBatch looks up multiple SPKIs efficiently.
// It runs all inputs through the in-RAM filter first, then sorts survivors by
// hash for near-sequential index I/O.
// The returned map keys are hex-encoded SHA-1 hashes of the input SPKIs.
func (db *DB) LookupBatch(spkis [][]byte) (map[[20]byte][]CertRecord, error) {
	type candidate struct {
		orig [20]byte
		sha1 [20]byte
	}

	var cands []candidate
	for _, s := range spkis {
		h := normalizeSPKI(s)
		var ha [20]byte
		copy(ha[:], h)
		var orig [20]byte
		if len(s) == 20 {
			copy(orig[:], s)
		} else {
			copy(orig[:], h)
		}
		if db.filterCheck(h) {
			cands = append(cands, candidate{orig, ha})
		}
	}

	sort.Slice(cands, func(i, j int) bool {
		return bytes.Compare(cands[i].sha1[:], cands[j].sha1[:]) < 0
	})

	results := make(map[[20]byte][]CertRecord)
	for _, c := range cands {
		offset, count, ok := db.binarySearch(c.sha1[:])
		if !ok {
			continue
		}
		recs, err := db.readCerts(offset, count)
		if err != nil {
			return nil, err
		}
		results[c.orig] = recs
	}
	return results, nil
}

func normalizeSPKI(spki []byte) []byte {
	if len(spki) == 20 {
		return spki
	}
	h := sha1.Sum(spki)
	return h[:]
}

func (db *DB) filterCheck(sha1Hash []byte) bool {
	f := db.filters[sha1Hash[0]]
	return f != nil && f.Contains(formats.FilterKey(sha1Hash))
}

func (db *DB) binarySearch(sha1Hash []byte) (uint64, uint16, bool) {
	lo, hi := int64(0), db.nSPKIs-1
	for lo <= hi {
		mid := (lo + hi) / 2
		start := mid * formats.IndexEntrySize
		key := db.indexData[start : start+20]
		cmp := bytes.Compare(key, sha1Hash)
		switch {
		case cmp == 0:
			_, offset, count := formats.UnpackIndexEntry(db.indexData[start : start+formats.IndexEntrySize])
			return offset, count, true
		case cmp < 0:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return 0, 0, false
}

func (db *DB) readCerts(offset uint64, count uint16) ([]CertRecord, error) {
	pos := int(offset)
	records := make([]CertRecord, 0, count)
	for i := 0; i < int(count); i++ {
		if pos+27 > len(db.certsData) {
			return nil, fmt.Errorf("certs.bin read out of bounds at offset %d", pos)
		}
		var fp [20]byte
		copy(fp[:], db.certsData[pos:pos+20])
		nb := formats.DaysToDate(uint32(db.certsData[pos+20]) |
			uint32(db.certsData[pos+21])<<8 | uint32(db.certsData[pos+22])<<16)
		na := formats.DaysToDate(uint32(db.certsData[pos+23]) |
			uint32(db.certsData[pos+24])<<8 | uint32(db.certsData[pos+25])<<16)
		cnLen := int(db.certsData[pos+26])
		pos += 27
		if pos+cnLen > len(db.certsData) {
			return nil, fmt.Errorf("certs.bin cn read out of bounds at offset %d", pos)
		}
		cn := string(db.certsData[pos : pos+cnLen])
		pos += cnLen
		records = append(records, CertRecord{
			FingerprintSHA1: fp,
			NotBefore:       nb,
			NotAfter:        na,
			CN:              cn,
		})
	}
	return records, nil
}

func (db *DB) loadFilters(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return err
	}
	if magic != formats.FilterMagic {
		return fmt.Errorf("not a cert-hunter-go filter file (magic %x)", magic)
	}

	var versionAndShards [3]byte
	if _, err := io.ReadFull(f, versionAndShards[:]); err != nil {
		return err
	}
	if versionAndShards[0] != formats.FilterVersion {
		return fmt.Errorf("unsupported filter version %d", versionAndShards[0])
	}
	numShards := int(binary.LittleEndian.Uint16(versionAndShards[1:3]))

	blobSizes := make([]uint32, numShards)
	if err := binary.Read(f, binary.LittleEndian, blobSizes); err != nil {
		return err
	}

	for i, size := range blobSizes {
		if size == 0 {
			continue
		}
		blob := make([]byte, size)
		if _, err := io.ReadFull(f, blob); err != nil {
			return fmt.Errorf("reading filter shard %d: %w", i, err)
		}
		filt, err := xorfilter.LoadBinaryFuse8(bytes.NewReader(blob))
		if err != nil {
			return fmt.Errorf("loading filter shard %d: %w", i, err)
		}
		db.filters[i] = filt
	}
	return nil
}

func mmapFile(path string) ([]byte, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if st.Size() == 0 {
		return nil, f, nil
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("mmap %s: %w", path, err)
	}
	return data, f, nil
}
