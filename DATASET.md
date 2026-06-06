---
title: "FindEvil Agent — Dataset Documentation"
project: "FindEvil Agent"
submission: "SANS Find Evil! Hackathon"
status: "Active"
last_updated: "2026-06-06"
---

# DATASET — FindEvil Agent

> Test evidence, hackathon-supplied case data, supported evidence types, and
> data-integrity practices for the **FindEvil Agent** MCP server.

---

## 1. Test Evidence (Our Generated Data)

The CI test suite exercises every tool against a deterministic, self-generated
artifact. This isolates the test environment from external data sources and
guarantees reproducible results across runners.

### 1.1 Generation Script

**Location:** `scripts/generate_test_evidence.sh`

The script produces a 10 MB ext2 filesystem image at
`/evidence/cases/test.raw`, populated with known string patterns that the
YARA / IOC / string-scanning tools can match against.

### 1.2 Reproducible Generation

Run locally (requires `sudo` for `mount` and `mkfs.ext2`):

```bash
# 1. From the repo root
./scripts/generate_test_evidence.sh

# 2. Verify the artifact
ls -lh /evidence/cases/test.raw
file /evidence/cases/test.raw
sudo debugfs -R "ls -l" /evidence/cases/test.raw
```

Or run the equivalent commands by hand:

```bash
EVIDENCE_DIR="/evidence/cases"
EVIDENCE_FILE="${EVIDENCE_DIR}/test.raw"
sudo mkdir -p "$EVIDENCE_DIR"

# 10 MB sparse file → ext2 filesystem
dd if=/dev/zero of="$EVIDENCE_FILE" bs=1M count=10
sudo mkfs.ext2 -F "$EVIDENCE_FILE" -L "TESTEVIDENCE"

# Mount, plant known strings, unmount
MOUNT_POINT=$(mktemp -d)
sudo mount -o loop "$EVIDENCE_FILE" "$MOUNT_POINT"
echo "This file contains malware sample data for testing" | sudo tee "$MOUNT_POINT/sample.txt"     > /dev/null
echo "Find Evil Agent forensic analysis system"          | sudo tee "$MOUNT_POINT/readme.txt"     > /dev/null
echo "Suspicious binary data with malware indicators"    | sudo dd    of="$MOUNT_POINT/suspicious.bin" bs=1 seek=0 2>/dev/null
echo "C2 server at 192.168.1.100:4444"                   | sudo tee -a "$MOUNT_POINT/suspicious.bin"            > /dev/null
echo "Find Evil - Memory Graph Forensics Tool"           | sudo tee "$MOUNT_POINT/tool.txt"       > /dev/null
sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

# Make readable by non-root processes
sudo chmod 644 "$EVIDENCE_FILE"
```

### 1.3 Image Properties

| Property            | Value                                           |
|---------------------|-------------------------------------------------|
| Path                | `/evidence/cases/test.raw`                      |
| Size                | 10 MB (10,485,760 bytes)                        |
| Filesystem          | ext2                                            |
| Volume label        | `TESTEVIDENCE`                                  |
| Magic               | Linux rev 1.0 ext2 filesystem data              |
| Block size          | 1024 (ext2 default for 10 MB)                   |
| Files               | `sample.txt`, `readme.txt`, `suspicious.bin`, `tool.txt` (plus `lost+found`) |
| Mode                | `0644` (world-readable, non-root safe)          |

### 1.4 Planted Contents (Ground Truth for Tests)

| File              | Content (verbatim)                                              | Used By |
|-------------------|------------------------------------------------------------------|---------|
| `sample.txt`      | `This file contains malware sample data for testing`             | YARA / string IOC tests |
| `readme.txt`      | `Find Evil Agent forensic analysis system`                       | String IOC tests         |
| `suspicious.bin`  | `Suspicious binary data with malware indicators\nC2 server at 192.168.1.100:4444` | C2-IOC, YARA tests |
| `tool.txt`        | `Find Evil - Memory Graph Forensics Tool`                       | Tool-name string tests   |

### 1.5 Why 10 MB

- Exercises the same code paths (block-I/O, ext2 mount, partition scan,
  file enumeration, YARA scan) as production-sized evidence.
- Fast to generate, mount, and tear down in CI (< 5 s per cycle).
- Small enough to keep the entire suite under 30 s; large enough to require
  multi-block reads and defeat naïve single-block parsing.

### 1.6 Test Integration

`tests/helpers.py` defines the single source of truth used by every test:

```python
EVIDENCE_ROOT = Path("/evidence/cases/test.raw")
HAS_EVIDENCE  = EVIDENCE_ROOT.exists()
```

Tests that require real evidence are gated with:

```python
@pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
```

This keeps the suite green on contributor machines where the artifact has
not yet been generated, while the CI workflow creates it on the runner.

---

## 2. SANS Starter Case Data (Hackathon-Provided)

The official SANS "Find Evil!" hackathon distributes a starter corpus of real
forensic artifacts at the following Egnyte link:

**🔗 https://sansorg.egnyte.com/fl/HhH7crTYT4JK**

### 2.1 Contents

| Asset class         | Examples                                                   |
|---------------------|------------------------------------------------------------|
| Disk images         | NTFS, ext4, FAT32 samples of compromised systems          |
| Memory captures     | Windows `lime`, Linux `lime`, raw `.dmp` / `.mem`          |
| Pre-configured VM   | Protocol SIFT POC workstation (SANS SIFT Workstation 3)    |

### 2.2 Intended Use

1. Download the archive locally (do **not** check the binaries into git).
2. Mount / load each artifact with Protocol SIFT tooling
   (`fls`, `icat`, `bulk_extractor`, `volatility`, `tshark`).
3. Run the FindEvil Agent against the same artifacts to compare findings.
4. Use the SANS-provided writeups as a reference baseline.

### 2.3 Storage on Disk (Recommended Layout)

```
/evidence/cases/
├── test.raw              # our generated 10 MB ext2 (CI)
├── sans-disk-001.raw     # SANS sample 1
├── sans-mem-001.lime     # SANS sample 2
└── sans-pcap-001.pcap    # SANS sample 3 (if provided)
```

Only the generated `test.raw` is tracked in the repository. The
SANS-supplied artifacts are excluded via `.gitignore` and
`.dockerignore` (see `evidence/` patterns below).

---

## 3. Evidence Types Supported

The FindEvil Agent MCP server exposes a namespaced tool family. Each
namespace corresponds to a forensic evidence class.

| Extension(s)              | Type     | Example        | Tool Prefix  | Underlying Tools                          |
|---------------------------|----------|----------------|--------------|-------------------------------------------|
| `.raw`, `.img`, `.dd`, `.001`, `.E01` | Disk image | `test.raw` | `fs_*`, `carve_*`, `extract_*` | `mmls`, `fls`, `icat`, `ewfinfo`, `testdisk`, `photorec`, `bulk_extractor`, `foremost`, `scalpel` |
| `.dmp`, `.mem`, `.lime`   | Memory   | `mem.dmp`      | `mem_*`      | `volatility`, `vol.py`, strings, YARA    |
| `.pcap`, `.pcapng`        | Network  | `capture.pcap` | `pcap_*`     | `tshark`, `tcpdump`, `ngrep`              |
| `.reg`, `.hive`           | Registry | `SAM.hive`     | `reg_*`      | `reglookup`, `chntpw`, `python-registry` |

### 3.1 Per-Tool Inventory (Representative)

| Namespace  | Tool Examples                                      | Purpose                                  |
|------------|----------------------------------------------------|------------------------------------------|
| `fs_*`     | `fs_partition_scan`, `fs_list_files`, `fs_filesystem_info`, `fs_extract_file` | Filesystem & partition inspection |
| `carve_*`  | `carve_files`                                       | File carving (sigs, types)               |
| `extract_*`| `extract_iocs`, `extract_strings`                   | Indicator / string extraction            |
| `mem_*`    | `mem_list_processes`, `mem_analyze`                 | Memory process & plugin analysis         |
| `pcap_*`   | `pcap_analyze`, `pcap_list_protocols`              | PCAP triage & protocol breakdown         |
| `reg_*`    | `reg_analyze_hive`                                  | Registry hive parsing                    |
| (root)     | `list_evidence`, `verify_hash`, `scan_yara`, `get_audit_logs` | Cross-cutting utilities      |

### 3.2 Tool-↔-Type Validation

The server validates evidence type **before** dispatching. Passing a disk
image to `mem_*` / `pcap_*` / `reg_*` either rejects the call or, where safe
(`mem_*` on a non-memory file), falls back to a string-based IOC scan with
an explicit `note: "string-based fallback"` field in the response. See
`TestWrongToolForEvidence` in `tests/test_edge_cases.py`.

---

## 4. Test Reproducibility

| Property                | Value / Behavior                                              |
|-------------------------|---------------------------------------------------------------|
| Evidence under test     | `/evidence/cases/test.raw` (10 MB ext2, deterministic)        |
| Generation time         | < 5 s (dd + mkfs.ext2 + 4 file creates)                       |
| Full pytest suite       | < 30 s on Ubuntu 24.04, single core                           |
| Test count              | ~70 cases across 8 modules (`test_edge_cases.py`, `test_forensic_tools.py`, `test_property_based.py`, …) |
| MCP server lifecycle    | One module-scoped singleton (avoids ~30 s of subprocess restart per test) |
| Random / nondeterminism | None — all inputs are baked into the image                    |
| CI workflow             | `.github/workflows/*.yml` runs `generate_test_evidence.sh` with `continue-on-error: true` for the setup step, then `pytest -q` against the artifact |
| Baseline (Protocol SIFT)| Unknown runtime; SIFT is a manual workstation, not a CI target |

### 4.1 Re-Running the Suite

```bash
# Generate evidence (idempotent — exits early if file exists and is non-empty)
./scripts/generate_test_evidence.sh

# Run the full edge-case + workflow + forensic-tools test suite
pytest -q tests/

# Run only the suite that needs the artifact
pytest -q tests/test_edge_cases.py
```

---

## 5. Ground Truth (Future Work)

The SANS starter archive ships **case data without ground truth** — the
participant is expected to derive "evil" vs. "not evil" by reading the
artifacts. That is fine for a writeup, but it prevents **automated accuracy
scoring** (precision / recall / F1).

### 5.1 Proposed Ground-Truth Image

To close that gap we plan to add a second generated artifact:

| Property            | Target                                                       |
|---------------------|--------------------------------------------------------------|
| Path                | `/evidence/cases/ground_truth.raw`                           |
| Size                | 1 GB ext4 (representative of a real workstation partition)  |
| Planted artifacts   | (a) files with `sha256` listed in `ground_truth_manifest.json`<br>(b) known-bad strings for YARA<br>(c) exfiltration markers (DNS lookups, base64-encoded HTTP bodies)<br>(d) a planted cron job + SSH key for persistence detection |
| Manifest format     | `ground_truth_manifest.json` — `{ "findings": [{ "category": "persistence", "path": "/etc/cron.d/evil", "expected_hash": "...", "yara_rule": "EvilCron" }, ...] }` |
| Scoring             | `pytest tests/test_accuracy.py -q` compares agent output vs. manifest, reports precision / recall / F1 per category |

### 5.2 Acceptance Criteria for the Ground-Truth Image

- Reproducible: byte-identical on re-generation (no timestamps, fixed seeds).
- Self-validating: `verify_ground_truth.py` recomputes the SHA-256 of every
  planted file and asserts equality with the manifest.
- Realistic: contains noise (clean files, benign logs, normal user activity)
  so that precision is non-trivial.
- License-clean: produced by our own script, so no redistribution concerns.

This work is tracked under the gap-analysis roadmap (`GAP_ANALYSIS.md`).

---

## 6. Data Integrity Practices

The agent is designed to be **safe to run against original evidence** in
production.

| Practice                                  | Enforcement                                                                 |
|-------------------------------------------|------------------------------------------------------------------------------|
| Evidence is **read-only**                 | Path validation in `path_validator` blocks any write/delete against `/evidence/**`; only `/results/**` accepts writes (carving, extraction output) |
| **No original data modification**         | All mutating tools accept an explicit `output_dir` that is constrained to `/results`; the source image is opened read-only (`rb`) and never truncated or renamed |
| Processing happens in memory or `/results`| In-memory pipelines for hashing, YARA, string scan; bulk artifacts (carved files, extracted registries) go to `/results/<case>/<tool>/` |
| **Audit trail**                           | Every tool call is logged via `get_audit_logs` with `{tool, timestamp, args, success, duration_ms, evidence_path, output_path}`; entries are append-only JSONL |
| Path-traversal defense                    | `TestPathTraversal` blocks `/etc/passwd`, `/etc/shadow`, `~/.bash_history`, null-byte injection, `..`-based escapes — see `tests/test_edge_cases.py::TestPathTraversal` |
| Output-dir jail                           | `TestCarvingEdgeCases` and `TestOutputDirSecurity` reject `/etc`, `/var`, `/tmp`, `/home`, `/root`, `/bin`, `/usr`, `/boot`, `/dev` as carving targets |
| Permission model                          | Test evidence is generated `0644`; server runs as a non-root user in CI; only `mount`/`mkfs` (in the generator script) require elevation |

---

## 7. Cross-Platform Testing

| Platform     | Status     | Notes                                                                  |
|--------------|------------|------------------------------------------------------------------------|
| Ubuntu 24.04 | ✔ CI       | Primary CI runner; `continue-on-error: true` on `generate_test_evidence.sh` (needs `sudo` for loop-mount) |
| macOS        | ✔ Local    | Validated via cross-platform `tool_resolver`; `ewfmount`, `mmls`, `fls` resolved via Homebrew paths |
| Windows      | ⚠ Partial  | Tool paths resolved dynamically by `tool_resolver`; ext2 mount not supported natively — use WSL2 or a Linux container for the test artifact |

### 7.1 Why It Still Works Cross-Platform

- The test suite calls the **MCP server** (a Python process) — not the
  underlying forensic binaries — so OS differences are absorbed by the
  tool-resolver layer.
- The `test.raw` artifact is a raw ext2 image, **not** a host filesystem
  path, so Windows runners can still byte-read it (e.g. via OSFMount,
  Arsenal Image Mounter, or a WSL2 helper).
- The `continue-on-error: true` flag on the evidence-generation step
  means tests that don't need the artifact (e.g. `TestPathTraversal`,
  `TestAuditTrail`) pass on any host.

### 7.2 Replicating the Artifact on macOS / Windows

```bash
# macOS — works the same; sudo may be a passwordless Touch ID prompt
./scripts/generate_test_evidence.sh

# Windows (WSL2) — install dosfstools / e2fsprogs first
sudo apt-get update && sudo apt-get install -y e2fsprogs
./scripts/generate_test_evidence.sh
```

---

## Appendix A — `.gitignore` Patterns

The following patterns keep large forensic artifacts out of version control
while letting the small `test.raw` be optionally tracked:

```gitignore
# Hackathon / forensic artifacts (do not commit)
/evidence/cases/*.raw
!/evidence/cases/test.raw
/evidence/cases/*.E01
/evidence/cases/*.dd
/evidence/cases/*.001
/evidence/cases/*.dmp
/evidence/cases/*.mem
/evidence/cases/*.lime
/evidence/cases/*.pcap
/evidence/cases/*.pcapng
/evidence/cases/*.hive
/evidence/cases/*.reg

# Generated runtime outputs
/results/**
/audit/*.jsonl
```

---

## Appendix B — Quick Reference

```bash
# Generate test evidence
./scripts/generate_test_evidence.sh

# Inspect the generated filesystem
sudo debugfs -R "ls -l" /evidence/cases/test.raw
sudo debugfs -R "cat sample.txt" /evidence/cases/test.raw

# Run the suite
pytest -q tests/

# Run a single class
pytest -q tests/test_edge_cases.py::TestPathTraversal
pytest -q tests/test_edge_cases.py::TestYaraEdgeCases

# Download SANS starter data
xdg-open "https://sansorg.egnyte.com/fl/HhH7crTYT4JK"   # Linux
open      "https://sansorg.egnyte.com/fl/HhH7crTYT4JK"   # macOS
```

---

*Last updated: 2026-06-06 — generated for the SANS Find Evil! hackathon submission.*
