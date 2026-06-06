#!/usr/bin/env python3
"""Helper to compute SHA256 hashes of ground truth content."""

import hashlib

# File 1: secret.txt
secret_content = "PLANTED_SECRET_MARKER_GT_001\n"
print(f"secret.txt -> {hashlib.sha256(secret_content.encode()).hexdigest()}")

# File 2: credentials.txt
cred_content = "user:admin password:PLANTED_CRED_GT_002\n"
print(f"credentials.txt -> {hashlib.sha256(cred_content.encode()).hexdigest()}")

# File 3: suspicious.bin (binary, no newline)
malware_content = b"PLANTED_MALWARE_GT_003"
print(f"suspicious.bin -> {hashlib.sha256(malware_content).hexdigest()}")

# File 4: normal.txt (control)
normal_content = "This is a normal file with no malicious content.\n"
print(f"normal.txt -> {hashlib.sha256(normal_content.encode()).hexdigest()}")
