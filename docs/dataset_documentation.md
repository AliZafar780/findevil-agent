# Dataset Documentation

> Evidence data used for testing and validation of the FindEvil Agent.

---

## Test Datasets

### Dataset 1: forensic.raw

| Property | Value |
|----------|-------|
| **Source** | Artificially created for this project |
| **File** | `/evidence/cases/forensic.raw` |
| **Size** | 100 MB |
| **Format** | Raw DD image |
| **Partition Table** | GPT |
| **Partitions** | 1 data partition (ext2) at sector 2048 |
| **Filesystem** | ext2 |
| **Contents** | `hello.txt` with 5 known indicator strings |
| **Purpose** | Integration testing, workflow validation, accuracy benchmarking |
| **Reproducibility** | See `scripts/setup.sh` and test tools |

#### Known Ground Truth (hello.txt)

```
Hello from Find Evil! This is a test file for DFIR analysis.
Suspicious activity detected at 2026-06-01 03:14:15 UTC
Malicious payload: C:\Windows\malware.exe
Registry key modified: HKLM\SYSTEM\CurrentControlSet\Services\malware
Network connection: 192.168.1.100:4444
```

### Dataset 2: test.raw

| Property | Value |
|----------|-------|
| **Source** | Artificially created |
| **File** | `/evidence/cases/test.raw` |
| **Size** | 50 MB |
| **Format** | Raw DD, no partition table |
| **Filesystem** | ext2 (whole disk) |
| **Purpose** | Testing tools without partition offset |

### Dataset 3: partitioned.raw *(deprecated)*

| Property | Value |
|----------|-------|
| **Source** | Artificially created, replaced by forensic.raw |
| **Status** | Legacy — kept for backward compatibility |

---

## Recommended Public Datasets for Further Testing

### NIST CFReDS (Computer Forensic Reference Data Sets)

| Dataset | URL | Size | Use Case |
|---------|-----|------|----------|
| **dfr-2005-fat32** | https://cfreds.nist.gov/ | ~100 MB | FAT32 file system forensics |
| **dfr-2005-ntfs** | https://cfreds.nist.gov/ | ~100 MB | NTFS file system forensics |
| **m57-patents** | https://cfreds.nist.gov/ | ~500 MB | Multi-user scenario |
| **nps-2009-domexusers** | https://cfreds.nist.gov/ | ~300 MB | User account forensics |

### SANS DFIR Challenge Images

| Challenge | Source | Type |
|-----------|--------|------|
| SANS DFIR Summit Challenges | sans.org/summit | Disk + Memory |
| Find Evil Contests | github.com/dfir-sans | Historical datasets |

### Memory Capture Datasets

| Dataset | Source | Type |
|---------|--------|------|
| Volatility Memory Samples | github.com/volatilityfoundation | Windows, Linux, Mac |
| Cuckoo Sandbox | cuckoosandbox.org | Malware execution traces |

---

## Reproducibility

All test datasets can be recreated using:
```bash
# From project root
bash scripts/setup.sh
```

For custom datasets:
```bash
dd if=/dev/zero of=/evidence/cases/custom.raw bs=1M count=100
echo -e "g\nn\n\n\n\nw" | fdisk /evidence/cases/custom.raw
# Format partition, add files, capture image
```

---

## Usage in Testing

Test datasets are used by:
1. `tests/test_server.py` — 9 integration tests
2. `tests/test_workflow.py` — 2 workflow tests
3. `benchmark_accuracy` MCP tool — ground truth comparison
