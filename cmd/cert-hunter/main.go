package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/gitguardian/cert-hunter/internal/build"
	"github.com/gitguardian/cert-hunter/internal/query"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "build":
		cmdBuild(os.Args[2:])
	case "lookup":
		cmdLookup(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `cert-hunter — Certificate Transparency SPKI indexer

Commands:
  build   <source> <output_dir> [flags]   Build index from a CT archive
  lookup  <db_dir> <spki_hex>...          Look up SPKI hashes

`)
}

func cmdBuild(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	workers := fs.Int("workers", runtime.NumCPU(), "tile-processing goroutines (also sets HTTP concurrency limit)")
	timing := fs.Bool("timing", false, "print per-phase timing after build")
	pubkey := fs.String("pubkey", "", "path to PEM public key file (required for https:// sources)")
	userAgent := fs.String("user-agent", "cert-hunter/0.1", "HTTP User-Agent; must contain an email or +https:// URL (sunlight requirement)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: cert-hunter build [flags] <source> <output_dir>\n\n")
		fmt.Fprintf(os.Stderr, "  source      https:// log URL, ct-archive .zip file, or directory of .zip files\n")
		fmt.Fprintf(os.Stderr, "  output_dir  directory to write filter.bin / index.bin / certs.bin\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fs.Usage()
		os.Exit(1)
	}
	source := fs.Arg(0)
	outputDir := fs.Arg(1)

	fmt.Printf("Building index from %s → %s ...\n", source, outputDir)
	if err := build.Build(source, outputDir, build.Options{
		Workers:    *workers,
		Timing:     *timing,
		PubKeyPath: *pubkey,
		UserAgent:  *userAgent,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Done.")
}

func cmdLookup(args []string) {
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	inputFile := fs.String("f", "", "file with one spki_hex per line")
	outFile := fs.String("out", "", "write results as JSONL to this file (default: human-readable stdout)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: cert-hunter lookup [flags] <db_dir> [<spki_hex>...]\n\n")
		fmt.Fprintf(os.Stderr, "  spki_hex  40-char hex SHA-1(SPKI), or longer hex for raw SPKI DER\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}
	dbDir := fs.Arg(0)

	// Collect hex inputs from positional args and/or -f file.
	var hexInputs []string
	hexInputs = append(hexInputs, fs.Args()[1:]...)
	if *inputFile != "" {
		lines, err := readLines(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", *inputFile, err)
			os.Exit(1)
		}
		hexInputs = append(hexInputs, lines...)
	}
	if len(hexInputs) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	spkis := make([][]byte, 0, len(hexInputs))
	for _, h := range hexInputs {
		b, err := hex.DecodeString(h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid hex %q: %v\n", h, err)
			os.Exit(1)
		}
		spkis = append(spkis, b)
	}

	db, err := query.Open(dbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	results, err := db.LookupBatch(spkis)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *outFile != "" {
		if err := writeLookupJSONL(*outFile, spkis, results); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Human-readable output.
	if len(results) == 0 {
		fmt.Println("No matches found.")
		return
	}
	for _, s := range spkis {
		key := spkiKey(s)
		recs, ok := results[key]
		if !ok {
			continue
		}
		fmt.Printf("SPKI SHA-1: %x\n", key)
		for _, r := range recs {
			fmt.Printf("  fingerprint (SHA-1): %x\n", r.FingerprintSHA1)
			fmt.Printf("  valid:               %s → %s\n",
				r.NotBefore.Format("2006-01-02"), r.NotAfter.Format("2006-01-02"))
			fmt.Printf("  CN:                  %s\n", r.CN)
		}
		fmt.Println()
	}
}

// writeLookupJSONL writes one JSON object per input SPKI to path.
// Each object has spki_sha1, found (bool), and certs (array, empty when not found).
func writeLookupJSONL(path string, spkis [][]byte, results map[[20]byte][]query.CertRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	bw := bufio.NewWriterSize(f, 4*1024*1024)
	enc := json.NewEncoder(bw)

	type certJSON struct {
		FingerprintSHA1 string `json:"fingerprint_sha1"`
		NotBefore       string `json:"not_before"`
		NotAfter        string `json:"not_after"`
		CN              string `json:"cn"`
	}
	type rowJSON struct {
		SPKISHA1 string     `json:"spki_sha1"`
		Found    bool       `json:"found"`
		Certs    []certJSON `json:"certs"`
	}

	for _, s := range spkis {
		key := spkiKey(s)
		recs := results[key]
		row := rowJSON{
			SPKISHA1: fmt.Sprintf("%x", key),
			Found:    len(recs) > 0,
			Certs:    make([]certJSON, 0, len(recs)),
		}
		for _, r := range recs {
			row.Certs = append(row.Certs, certJSON{
				FingerprintSHA1: fmt.Sprintf("%x", r.FingerprintSHA1),
				NotBefore:       r.NotBefore.Format("2006-01-02"),
				NotAfter:        r.NotAfter.Format("2006-01-02"),
				CN:              r.CN,
			})
		}
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func spkiKey(s []byte) [20]byte {
	if len(s) == 20 {
		var k [20]byte
		copy(k[:], s)
		return k
	}
	return sha1.Sum(s)
}

// readLines reads a file and returns non-empty, non-comment lines.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
