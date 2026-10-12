# file-triage-tool

A small static triage script for a single file. It never executes the file; it only reads its bytes.

## What it reports

- File name, size and SHA-256
- File type from magic bytes (PE, PDF, PNG, ZIP, JPEG, ELF, ...)
- Extension vs. detected type mismatch
- Shannon entropy and a Low / Medium / High classification
- Printable ASCII strings matching suspicious keywords (`powershell`, `cmd.exe`, `CreateProcess`, URLs)

## Usage

Requires Python 3.8+ (standard library only).

```bash
python spy.py
```

The script reads `sample.bin` from the current directory and writes `triage_report.json`.

## Sample

`sample.bin` is a harmless training file: a few printable strings padded with random bytes. It is not malware.
