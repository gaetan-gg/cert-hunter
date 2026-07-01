// csv-spki reads a CSV file, computes SHA-1(SubjectPublicKeyInfo) for the
// private key in a named column, and writes each row as a JSON object (JSONL)
// with the original fields plus "spki_sha1" and "error". Key parsing runs in
// parallel; output order is not guaranteed.
//
// Usage:
//
//	csv-spki [-out output.jsonl] [-workers N] <csv_file> <key_column>
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

func main() {
	var outPath string
	var workers int
	flag.StringVar(&outPath, "out", "", "write JSONL to this file (default: stdout)")
	flag.IntVar(&workers, "workers", runtime.NumCPU(), "parallel key-parsing goroutines")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: csv-spki [flags] <csv_file> <key_column>\n\n")
		fmt.Fprintf(os.Stderr, "  csv_file    path to the input CSV\n")
		fmt.Fprintf(os.Stderr, "  key_column  column containing PEM-encoded private keys\n\n")
		fmt.Fprintf(os.Stderr, "Each row is written as a JSON object with all original fields plus\n")
		fmt.Fprintf(os.Stderr, "\"spki_sha1\" (40-char hex SHA-1 of SubjectPublicKeyInfo DER) and\n")
		fmt.Fprintf(os.Stderr, "\"error\" (null on success, reason string on failure).\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	out := os.Stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	if err := run(flag.Arg(0), flag.Arg(1), workers, out); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type job struct {
	lineNum int
	row     []string
	keyPEM  string
}

func run(csvPath, keyCol string, workers int, out io.Writer) error {
	f, err := os.Open(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1

	headers, err := r.Read()
	if err != nil {
		return fmt.Errorf("reading CSV header: %w", err)
	}
	for i := range headers {
		headers[i] = strings.TrimSpace(strings.TrimPrefix(headers[i], "\xef\xbb\xbf"))
	}

	colIdx := -1
	for i, h := range headers {
		if h == keyCol {
			colIdx = i
			break
		}
	}
	if colIdx == -1 {
		return fmt.Errorf("column %q not found; available: %s", keyCol, strings.Join(headers, ", "))
	}

	// Pre-marshal JSON header keys once; shared read-only across workers.
	headerKeys := make([][]byte, len(headers))
	for i, h := range headers {
		headerKeys[i], _ = json.Marshal(h)
	}

	bw := bufio.NewWriterSize(out, 4*1024*1024)
	defer bw.Flush()

	var (
		mu     sync.Mutex     // serialises writes to bw
		failed atomic.Int64
		total  atomic.Int64
		wg     sync.WaitGroup
	)

	jobCh := make(chan job, workers*4)

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				line := buildLine(j, headerKeys)
				mu.Lock()
				bw.Write(line)
				mu.Unlock()
			}
		}()
	}

	var csvErr error
	for lineNum := 2; ; lineNum++ {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			csvErr = fmt.Errorf("line %d: %w", lineNum, err)
			break
		}
		total.Add(1)

		var keyPEM string
		if colIdx < len(row) {
			keyPEM = row[colIdx]
		}
		jobCh <- job{lineNum: lineNum, row: row, keyPEM: keyPEM}
	}
	close(jobCh)
	wg.Wait()

	if n := failed.Load(); n > 0 {
		fmt.Fprintf(os.Stderr, "%d / %d rows had no parseable key\n", n, total.Load())
	}
	return csvErr
}

// buildLine computes the SPKI hash for job j and returns a complete JSON line.
func buildLine(j job, headerKeys [][]byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range headerKeys {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(k)
		buf.WriteByte(':')
		val := ""
		if i < len(j.row) {
			val = j.row[i]
		}
		valJSON, _ := json.Marshal(val)
		buf.Write(valJSON)
	}

	hash, parseErr := spkiSHA1(j.keyPEM)

	buf.WriteString(`,"spki_sha1":`)
	if parseErr != nil {
		buf.WriteString("null")
	} else {
		fmt.Fprintf(&buf, `"%x"`, hash)
	}

	buf.WriteString(`,"error":`)
	if parseErr != nil {
		errJSON, _ := json.Marshal(parseErr.Error())
		buf.Write(errJSON)
		fmt.Fprintf(os.Stderr, "warning: line %d: %v\n", j.lineNum, parseErr)
	} else {
		buf.WriteString("null")
	}

	buf.WriteString("}\n")
	return buf.Bytes()
}

// spkiSHA1 parses a PEM private key and returns SHA-1(SPKI DER).
// It handles plain PEM (with real or escaped \n) and base64-encoded PEM.
func spkiSHA1(pemStr string) ([20]byte, error) {
	pemStr = strings.TrimSpace(pemStr)
	if pemStr == "" {
		return [20]byte{}, fmt.Errorf("empty value")
	}

	block := decodePEMBlock(pemStr)
	if block == nil {
		return [20]byte{}, fmt.Errorf("no PEM block found (tried plain and base64-encoded)")
	}

	pub, err := publicKeyFromBlock(block)
	if err != nil {
		return [20]byte{}, err
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [20]byte{}, fmt.Errorf("marshaling SPKI: %w", err)
	}
	return sha1.Sum(der), nil
}

// decodePEMBlock extracts a PEM block from s.
// It first tries a direct parse (normalising escape sequences), then falls back
// to base64-decoding the value and parsing the result.
func decodePEMBlock(s string) *pem.Block {
	// 1. Direct parse after normalising newline escape sequences.
	// Order matters: handle \r\n as a unit before \r or \n individually,
	// so a literal "\r\n" sequence doesn't leave a stray \r in the PEM body.
	candidate := s
	candidate = strings.ReplaceAll(candidate, `\r\n`, "\n")
	candidate = strings.ReplaceAll(candidate, `\r`, "")
	candidate = strings.ReplaceAll(candidate, `\n`, "\n")
	// Also clean up any actual CR bytes (e.g. Windows line endings stored as-is).
	candidate = strings.ReplaceAll(candidate, "\r\n", "\n")
	candidate = strings.ReplaceAll(candidate, "\r", "")
	if block, _ := pem.Decode([]byte(candidate)); block != nil {
		return block
	}

	// 2. Base64-encoded PEM: strip whitespace, decode, then pem.Decode.
	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		decoded, err := enc.DecodeString(stripped)
		if err != nil {
			continue
		}
		if block, _ := pem.Decode(decoded); block != nil {
			return block
		}
	}

	return nil
}

func publicKeyFromBlock(block *pem.Block) (crypto.PublicKey, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#1: %w", err)
		}
		return k.Public(), nil

	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("EC: %w", err)
		}
		return k.Public(), nil

	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#8: %w", err)
		}
		type publicer interface{ Public() crypto.PublicKey }
		pk, ok := k.(publicer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key type %T does not implement Public()", k)
		}
		return pk.Public(), nil

	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}
