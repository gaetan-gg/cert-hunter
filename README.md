# cert-hunter

cert-hunter builds a local, queryable index over Certificate Transparency logs (static-ct/sunlight archives) keyed by SHA-1(SubjectPublicKeyInfo), so you can quickly check whether a given public key (e.g. one recovered from a leaked private key) has ever been used in a publicly logged certificate.

> [!WARNING]
> This is an utterly vibe-coded proof of concept. It is not tested, not reviewed, and will not be maintained. Use at your own risk.
> Built as a companion PoC for Pass The Salt 2026 conference "Private Key Leaks in the Wild: from PTS to RWC, and back to PTS"
> https://www.pass-the-salt.org/ 

## Usage

Build an index from a CT log (HTTPS source, a ct-archive `.zip`, or a directory of `.zip` files):

```
Usage: cert-hunter build [flags] <source> <output_dir>

  source      https:// log URL, ct-archive .zip file, or directory of .zip files
  output_dir  directory to write filter.bin / index.bin / certs.bin

  -pubkey string
    	path to PEM public key file (required for https:// sources)
  -timing
    	print per-phase timing after build
  -user-agent string
    	HTTP User-Agent; must contain an email or +https:// URL (sunlight requirement) (default "cert-hunter/0.1")
  -workers int
    	tile-processing goroutines (also sets HTTP concurrency limit) (default 96)

```

Look up one or more SPKI SHA-1 hashes against a built index:

```
Usage: cert-hunter lookup [flags] <db_dir> [<spki_hex>...]

  spki_hex  40-char hex SHA-1(SPKI), or longer hex for raw SPKI DER

  -f string
    	file with one spki_hex per line
  -out string
    	write results as JSONL to this file (default: human-readable stdout)
```

### csv-spki helper

Compute SPKI SHA-1 hashes for private keys stored in a CSV column, output as JSONL:

```
csv-spki [flags] <csv_file> <key_column>
```

The resulting `spki_sha1` values can be fed into `cert-hunter lookup -f`.
