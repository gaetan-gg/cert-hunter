package formats

import (
	"encoding/binary"
	"time"
)

const (
	NumShards      = 256
	IndexEntrySize = 27 // spki_sha1[20] + offset[5 LE] + count[2 LE]
	MaxCNLen       = 253
)

// FilterMagic identifies a cert-hunter-go filter file.
// Distinct from the Python format ('CHXF') since the filter serialisation differs.
var FilterMagic = [4]byte{'C', 'H', 'G', 'F'}

const FilterVersion byte = 1

// DateToDays converts a UTC time to days since Unix epoch, clamped to uint24.
func DateToDays(t time.Time) uint32 {
	d := t.UTC().Unix() / 86400
	if d < 0 {
		return 0
	}
	if d > 0xFFFFFF {
		return 0xFFFFFF
	}
	return uint32(d)
}

// DaysToDate converts days-since-epoch back to a time.Time (midnight UTC).
func DaysToDate(days uint32) time.Time {
	return time.Unix(int64(days)*86400, 0).UTC()
}

// FilterKey returns the big-endian uint64 of the first 8 bytes of a SHA-1 hash.
// This is the key used to look up an SPKI in the per-shard Fuse8 filter.
func FilterKey(sha1 []byte) uint64 {
	return binary.BigEndian.Uint64(sha1[:8])
}

// PackIndexEntry writes a 27-byte index entry into buf.
// buf must be at least IndexEntrySize bytes long.
func PackIndexEntry(buf []byte, spkiSHA1 []byte, offset uint64, count uint16) {
	copy(buf[:20], spkiSHA1)
	buf[20] = byte(offset)
	buf[21] = byte(offset >> 8)
	buf[22] = byte(offset >> 16)
	buf[23] = byte(offset >> 24)
	buf[24] = byte(offset >> 32)
	binary.LittleEndian.PutUint16(buf[25:27], count)
}

// UnpackIndexEntry reads a 27-byte index entry from buf.
func UnpackIndexEntry(buf []byte) (spkiSHA1 []byte, offset uint64, count uint16) {
	spkiSHA1 = buf[:20]
	offset = uint64(buf[20]) | uint64(buf[21])<<8 | uint64(buf[22])<<16 |
		uint64(buf[23])<<24 | uint64(buf[24])<<32
	count = binary.LittleEndian.Uint16(buf[25:27])
	return
}
