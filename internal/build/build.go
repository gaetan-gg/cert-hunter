package build

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sunlight "filippo.io/sunlight"
	torchwood "filippo.io/torchwood"
	xorfilter "github.com/FastFilter/xorfilter"
	tlog "golang.org/x/mod/sumdb/tlog"

	"github.com/gaetan-gg/cert-hunter/internal/formats"
)

// Options controls the build process.
type Options struct {
	Workers    int
	Timing     bool
	PubKeyPath string // optional: PEM public key for checkpoint signature verification
	UserAgent  string // optional: overrides default; must contain email or +https:// URL if set
}

// Build indexes a CT source into outputDir.
//
// source may be:
//   - https:// or http:// URL of a static-ct log  (requires opts.PubKeyPath)
//   - path to a ct-archive .zip file
//   - path to a directory containing ct-archive .zip files
func Build(source, outputDir string, opts Options) error {
	if opts.Workers < 1 {
		opts.Workers = 1
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	// Always wipe the shard dir so a previous interrupted run's partial files
	// (unflushed bufio.Writer data) can't corrupt this run via O_APPEND.
	shardDir := filepath.Join(outputDir, "_shards")
	if err := os.RemoveAll(shardDir); err != nil {
		return fmt.Errorf("cleaning shard dir: %w", err)
	}
	if err := os.MkdirAll(shardDir, 0o755); err != nil {
		return fmt.Errorf("creating shard dir: %w", err)
	}

	// Phase 1
	t0 := time.Now()
	var count int64

	ctx := context.Background()
	isHTTP := strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://")

	if isHTTP {
		if err := buildFromLog(ctx, source, shardDir, opts, &count); err != nil {
			return err
		}
	} else if info, err := os.Stat(source); err != nil {
		return fmt.Errorf("opening source: %w", err)
	} else if info.IsDir() {
		if err := buildFromDir(source, shardDir, opts.Workers, &count); err != nil {
			return err
		}
	} else {
		if err := buildFromZip(source, shardDir, opts.Workers, &count); err != nil {
			return err
		}
	}
	p1Dur := time.Since(t0)

	// Phase 2
	t1 := time.Now()
	filterBlobs, shardCount, err := phase2(outputDir, shardDir)
	if err != nil {
		return fmt.Errorf("phase 2: %w", err)
	}
	p2Dur := time.Since(t1)

	// Phase 3
	t2 := time.Now()
	if err := phase3(outputDir, filterBlobs); err != nil {
		return fmt.Errorf("phase 3: %w", err)
	}
	p3Dur := time.Since(t2)

	if opts.Timing {
		rate := float64(count) / p1Dur.Seconds()
		fmt.Println()
		fmt.Println("=== cert-hunter build timing ===")
		fmt.Println()
		fmt.Printf("Phase 1  stream      %8.2fs  ·  %s entries  ·  %d workers  ·  %.0f entries/s\n",
			p1Dur.Seconds(), commaSep(count), opts.Workers, rate)
		fmt.Printf("Phase 2  sort/index  %8.2fs  ·  %d non-empty shards\n",
			p2Dur.Seconds(), shardCount)
		fmt.Printf("Phase 3  filter      %8.2fs\n", p3Dur.Seconds())
		fmt.Println()
		fmt.Printf("Total                %8.2fs\n", (p1Dur + p2Dur + p3Dur).Seconds())
		fmt.Println()
	}
	return nil
}

// buildFromLog streams a live static-ct log over HTTP.
// Tile-level concurrency is controlled by opts.Workers via sunlight's ConcurrencyLimit;
// entry processing runs in a single goroutine (CPU is not the bottleneck — network is).
//
// If opts.PubKeyPath is set, the checkpoint signature is verified against that key.
// If not, the checkpoint is parsed without signature verification (tree size and root
// hash are still used, but their authenticity is not checked).
func buildFromLog(ctx context.Context, source, shardDir string, opts Options, total *int64) error {
	ua := opts.UserAgent
	if ua == "" {
		ua = "cert-hunter/0.1"
	}

	var pubKey crypto.PublicKey
	if opts.PubKeyPath != "" {
		var err error
		pubKey, err = loadPubKey(opts.PubKeyPath)
		if err != nil {
			return fmt.Errorf("loading pubkey: %w", err)
		}
	}

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix:          source,
		PublicKey:                 pubKey,
		UserAgent:                 ua,
		ConcurrencyLimit:          opts.Workers,
		AllowRFC6962ArchivalLeafs: true,
	})
	if err != nil {
		return fmt.Errorf("creating sunlight client: %w", err)
	}

	// Get the tree: verified if a public key was given, unverified otherwise.
	var tree tlog.Tree
	if pubKey != nil {
		checkpoint, _, err := client.Checkpoint(ctx)
		if err != nil {
			return fmt.Errorf("fetching checkpoint: %w", err)
		}
		tree = checkpoint.Tree
	} else {
		raw, err := client.TileReader().ReadEndpoint(ctx, "checkpoint")
		if err != nil {
			return fmt.Errorf("fetching checkpoint: %w", err)
		}
		tree, err = parseCheckpointTree(raw)
		if err != nil {
			return fmt.Errorf("parsing checkpoint: %w", err)
		}
	}
	// Build the list of all data tiles. Bypassing client.Entries() avoids its
	// per-entry overhead: hash tile fetches for Merkle verification and a
	// context.WithTimeout reset on every yield. We already accept unverified
	// data when --pubkey is not set, so this is consistent with existing policy.
	tileW := int64(torchwood.TileWidth)
	numFullTiles := tree.N / tileW
	partialCount := int(tree.N % tileW)

	allTiles := make([]tlog.Tile, 0, numFullTiles+1)
	for n := int64(0); n < numFullTiles; n++ {
		allTiles = append(allTiles, tlog.Tile{H: torchwood.TileHeight, L: -1, N: n, W: torchwood.TileWidth})
	}
	if partialCount > 0 {
		allTiles = append(allTiles, tlog.Tile{H: torchwood.TileHeight, L: -1, N: numFullTiles, W: partialCount})
	}

	fmt.Fprintf(os.Stderr, "log size: %s entries  (%d tiles)\n", commaSep(tree.N), len(allTiles))

	st := newStatus("Phase 1", int64(len(allTiles)), "entries")
	defer st.stop()

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	tileCh := make(chan tlog.Tile, opts.Workers*2)
	var wg sync.WaitGroup
	var firstWorkerErr error
	var errMu sync.Mutex

	tr := client.TileReader()

	for id := 0; id < opts.Workers; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ws, wsErr := newWorkerState(id, shardDir)
			if wsErr != nil {
				errMu.Lock()
				if firstWorkerErr == nil {
					firstWorkerErr = wsErr
				}
				errMu.Unlock()
				cancel()
				return
			}
			ws.entryProgress = &st.extra
			defer ws.close()

			for tile := range tileCh {
				data, err := tr.ReadTiles(innerCtx, []tlog.Tile{tile})
				if err != nil {
					if innerCtx.Err() != nil {
						return
					}
					fmt.Fprintf(os.Stderr, "warning: tile %d: %v\n", tile.N, err)
					st.add(1)
					continue
				}
				if err := ws.processTileData(data[0]); err != nil {
					fmt.Fprintf(os.Stderr, "warning: tile %d: %v\n", tile.N, err)
				}
				st.add(1)
			}
			atomic.AddInt64(total, ws.count)
		}(id)
	}

feed:
	for _, tile := range allTiles {
		select {
		case tileCh <- tile:
		case <-innerCtx.Done():
			break feed
		}
	}
	close(tileCh)
	wg.Wait()

	return firstWorkerErr
}

// parseCheckpointTree extracts tree size and root hash from a checkpoint note
// without verifying the signature. The checkpoint format is:
//
//	<log name>
//	<tree size>
//	<base64 root hash>
//	(blank line + signature lines)
func parseCheckpointTree(data []byte) (tlog.Tree, error) {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 3 {
		return tlog.Tree{}, fmt.Errorf("checkpoint has fewer than 3 lines")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return tlog.Tree{}, fmt.Errorf("parsing tree size %q: %w", lines[1], err)
	}
	hashBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[2]))
	if err != nil {
		return tlog.Tree{}, fmt.Errorf("decoding root hash: %w", err)
	}
	if len(hashBytes) != 32 {
		return tlog.Tree{}, fmt.Errorf("root hash is %d bytes, want 32", len(hashBytes))
	}
	var h tlog.Hash
	copy(h[:], hashBytes)
	return tlog.Tree{N: n, Hash: h}, nil
}

func loadPubKey(path string) (crypto.PublicKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// buildFromDir processes all .zip files in dir.
func buildFromDir(dir, shardDir string, workers int, total *int64) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		var n int64
		if err := buildFromZip(filepath.Join(dir, e.Name()), shardDir, workers, &n); err != nil {
			return err
		}
		atomic.AddInt64(total, n)
	}
	return nil
}

// buildFromZip processes tiles from a single ct-archive zip file.
func buildFromZip(zipPath, shardDir string, workers int, total *int64) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("opening zip %s: %w", zipPath, err)
	}
	defer zr.Close()

	// Collect data tile entries.
	var tiles []*zip.File
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "tile/data/") {
			tiles = append(tiles, f)
		}
	}
	if len(tiles) == 0 {
		return nil
	}

	st := newStatus("Phase 1  "+filepath.Base(zipPath), int64(len(tiles)), "entries")
	defer st.stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tileCh := make(chan *zip.File, workers*2)
	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	for id := 0; id < workers; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ws, wsErr := newWorkerState(id, shardDir)
			if wsErr != nil {
				select {
				case errCh <- wsErr:
				default:
				}
				cancel()
				return
			}
			ws.entryProgress = &st.extra
			defer ws.close()

			for tf := range tileCh {
				if err := ws.processTile(tf); err != nil {
					// Per-tile errors are non-fatal: log and continue.
					fmt.Fprintf(os.Stderr, "warning: tile %s: %v\n", tf.Name, err)
				}
				st.add(1) // tile done
			}
			atomic.AddInt64(total, ws.count)
		}(id)
	}

feed:
	for _, t := range tiles {
		select {
		case tileCh <- t:
		case <-ctx.Done():
			break feed
		}
	}
	close(tileCh)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// workerState holds per-goroutine Phase 1 state.
type workerState struct {
	id            int
	dir           string
	files         [formats.NumShards]*os.File
	bufs          [formats.NumShards]*bufio.Writer
	count         int64
	entryProgress *atomic.Int64 // optional shared counter for live progress display
}

func newWorkerState(id int, shardBase string) (*workerState, error) {
	dir := filepath.Join(shardBase, fmt.Sprintf("w%02d", id))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("worker %d shard dir: %w", id, err)
	}
	return &workerState{id: id, dir: dir}, nil
}

func (ws *workerState) shardFile(idx int) (*bufio.Writer, error) {
	if ws.bufs[idx] != nil {
		return ws.bufs[idx], nil
	}
	f, err := os.OpenFile(
		filepath.Join(ws.dir, fmt.Sprintf("%02x.bin", idx)),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	ws.files[idx] = f
	ws.bufs[idx] = bufio.NewWriterSize(f, 256*1024)
	return ws.bufs[idx], nil
}

func (ws *workerState) close() {
	for i, b := range ws.bufs {
		if b != nil {
			b.Flush()
			ws.files[i].Close()
		}
	}
}

func (ws *workerState) processTile(tf *zip.File) error {
	rc, err := tf.Open()
	if err != nil {
		return err
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return err
	}
	return ws.processTileData(data)
}

func (ws *workerState) processTileData(data []byte) error {
	for len(data) > 0 {
		entry, rest, err := sunlight.ReadTileLeafMaybeArchival(data)
		if err != nil {
			break
		}
		data = rest
		if err := ws.writeEntry(entry); err != nil {
			return err
		}
	}
	return nil
}

// record layout written to shard temp files:
// len(payload)[2 LE] | spki_sha1[20] | fp_sha1[20] | not_before[3 LE] | not_after[3 LE] | cn_len[1] | cn[cn_len]
func (ws *workerState) writeEntry(entry *sunlight.LogEntry) error {
	var rawCert []byte
	if entry.IsPrecert {
		rawCert = entry.PreCertificate
	} else {
		rawCert = entry.Certificate
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil // skip unparseable certs
	}

	spkiHash := sha1.Sum(cert.RawSubjectPublicKeyInfo)
	fpHash := sha1.Sum(rawCert)
	notBefore := formats.DateToDays(cert.NotBefore)
	notAfter := formats.DateToDays(cert.NotAfter)
	cn := extractCN(cert)
	cnBytes := []byte(cn)
	if len(cnBytes) > formats.MaxCNLen {
		cnBytes = cnBytes[:formats.MaxCNLen]
	}

	payloadLen := 20 + 20 + 3 + 3 + 1 + len(cnBytes)
	buf := make([]byte, 2+payloadLen)
	binary.LittleEndian.PutUint16(buf[:2], uint16(payloadLen))
	off := 2
	copy(buf[off:], spkiHash[:])
	off += 20
	copy(buf[off:], fpHash[:])
	off += 20
	buf[off] = byte(notBefore)
	buf[off+1] = byte(notBefore >> 8)
	buf[off+2] = byte(notBefore >> 16)
	off += 3
	buf[off] = byte(notAfter)
	buf[off+1] = byte(notAfter >> 8)
	buf[off+2] = byte(notAfter >> 16)
	off += 3
	buf[off] = byte(len(cnBytes))
	off++
	copy(buf[off:], cnBytes)

	shardIdx := int(spkiHash[0])
	w, err := ws.shardFile(shardIdx)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	ws.count++
	if ws.entryProgress != nil {
		ws.entryProgress.Add(1)
	}
	return err
}

func extractCN(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return ""
}

// phase2 sorts each shard, writes index.bin + certs.bin, builds per-shard filters.
// Returns filter blobs (nil for empty shards) and the count of non-empty shards.
func phase2(outputDir, shardDir string) ([][]byte, int, error) {
	workerDirs, err := filepath.Glob(filepath.Join(shardDir, "w*"))
	if err != nil {
		return nil, 0, err
	}

	indexFile, err := os.Create(filepath.Join(outputDir, "index.bin"))
	if err != nil {
		return nil, 0, err
	}
	defer indexFile.Close()

	certsFile, err := os.Create(filepath.Join(outputDir, "certs.bin"))
	if err != nil {
		return nil, 0, err
	}
	defer certsFile.Close()

	indexBuf := bufio.NewWriterSize(indexFile, 4*1024*1024)
	certsBuf := bufio.NewWriterSize(certsFile, 4*1024*1024)

	filterBlobs := make([][]byte, formats.NumShards)
	indexEntry := make([]byte, formats.IndexEntrySize)
	var certsOffset uint64
	nonEmpty := 0

	st := newStatus("Phase 2", formats.NumShards, "")
	defer st.stop()

	for shard := 0; shard < formats.NumShards; shard++ {
		records, err := loadShardRecords(workerDirs, shard)
		if err != nil {
			return nil, 0, fmt.Errorf("shard %02x: %w", shard, err)
		}
		if len(records) == 0 {
			st.add(1)
			continue
		}
		nonEmpty++

		sort.Slice(records, func(i, j int) bool {
			return bytes.Compare(records[i][:20], records[j][:20]) < 0
		})

		var filterKeys []uint64
		i := 0
		for i < len(records) {
			spki := records[i][:20]
			groupOffset := certsOffset
			var groupCount uint16

			for i < len(records) && bytes.Equal(records[i][:20], spki) {
				certRec := records[i][20:] // fp[20]+nb[3]+na[3]+cnlen[1]+cn
				certsBuf.Write(certRec)
				certsOffset += uint64(len(certRec))
				if groupCount < 0xFFFF {
					groupCount++
				}
				i++
			}

			formats.PackIndexEntry(indexEntry, spki, groupOffset, groupCount)
			indexBuf.Write(indexEntry)
			filterKeys = append(filterKeys, formats.FilterKey(spki))
		}
		records = nil

		filt, err := xorfilter.PopulateBinaryFuse8(filterKeys)
		if err != nil {
			return nil, 0, fmt.Errorf("shard %02x filter: %w", shard, err)
		}
		var blob bytes.Buffer
		if err := filt.Save(&blob); err != nil {
			return nil, 0, err
		}
		filterBlobs[shard] = blob.Bytes()
		st.add(1)
	}

	if err := indexBuf.Flush(); err != nil {
		return nil, 0, err
	}
	if err := certsBuf.Flush(); err != nil {
		return nil, 0, err
	}

	if err := os.RemoveAll(shardDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cleanup shard dir: %v\n", err)
	}

	return filterBlobs, nonEmpty, nil
}

func loadShardRecords(workerDirs []string, shard int) ([][]byte, error) {
	name := fmt.Sprintf("%02x.bin", shard)
	var records [][]byte
	for _, wdir := range workerDirs {
		data, err := os.ReadFile(filepath.Join(wdir, name))
		if os.IsNotExist(err) || len(data) == 0 {
			continue
		}
		if err != nil {
			return nil, err
		}
		for pos := 0; pos < len(data); {
			if pos+2 > len(data) {
				break
			}
			recLen := int(binary.LittleEndian.Uint16(data[pos:]))
			pos += 2
			const minRecLen = 20 + 20 + 3 + 3 + 1 // spki+fp+nb+na+cnlen
			if recLen < minRecLen {
				return nil, fmt.Errorf("shard %02x: corrupt record in %s at offset %d (recLen=%d)",
					shard, wdir, pos-2, recLen)
			}
			if pos+recLen > len(data) {
				break
			}
			rec := make([]byte, recLen)
			copy(rec, data[pos:pos+recLen])
			records = append(records, rec)
			pos += recLen
		}
	}
	return records, nil
}

// phase3 assembles filter.bin from per-shard blobs.
func phase3(outputDir string, filterBlobs [][]byte) error {
	filterFile, err := os.Create(filepath.Join(outputDir, "filter.bin"))
	if err != nil {
		return err
	}
	defer filterFile.Close()
	buf := bufio.NewWriterSize(filterFile, 1*1024*1024)

	buf.Write(formats.FilterMagic[:])
	buf.WriteByte(formats.FilterVersion)
	binary.Write(buf, binary.LittleEndian, uint16(formats.NumShards))

	for _, blob := range filterBlobs {
		binary.Write(buf, binary.LittleEndian, uint32(len(blob)))
	}
	for _, blob := range filterBlobs {
		if len(blob) > 0 {
			buf.Write(blob)
		}
	}
	return buf.Flush()
}

func commaSep(n int64) string {
	s := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(s)+len(s)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}
