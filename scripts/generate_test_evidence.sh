#!/usr/bin/env bash
set -euo pipefail

EVIDENCE_DIR="/evidence/cases"
EVIDENCE_FILE="${EVIDENCE_DIR}/test.raw"

echo "🔧 Generating test evidence file..."

# Create directory
sudo mkdir -p "$EVIDENCE_DIR"

# Check if already exists
if [ -f "$EVIDENCE_FILE" ] && [ "$(stat -c%s "$EVIDENCE_FILE" 2>/dev/null)" -gt 0 ]; then
    echo "✅ Test evidence already exists: $(stat -c%s "$EVIDENCE_FILE") bytes"
    exit 0
fi

# Create a 10MB sparse file
dd if=/dev/zero of="$EVIDENCE_FILE" bs=1M count=10 status=progress 2>/dev/null

# Make ext2 filesystem
sudo mkfs.ext2 -F "$EVIDENCE_FILE" -L "TESTEVIDENCE" 2>/dev/null

# Mount and populate with known strings
MOUNT_POINT=$(mktemp -d)
sudo mount -o loop "$EVIDENCE_FILE" "$MOUNT_POINT"

# Create files with known content that test patterns can match
echo "This file contains malware sample data for testing" | sudo tee "$MOUNT_POINT/sample.txt" > /dev/null
echo "Find Evil Agent forensic analysis system" | sudo tee "$MOUNT_POINT/readme.txt" > /dev/null
echo "Suspicious binary data with malware indicators" | sudo dd of="$MOUNT_POINT/suspicious.bin" bs=1 seek=0 2>/dev/null
echo "C2 server at 192.168.1.100:4444" | sudo tee -a "$MOUNT_POINT/suspicious.bin" > /dev/null
echo "Find Evil - Memory Graph Forensics Tool" | sudo tee "$MOUNT_POINT/tool.txt" > /dev/null

# Unmount
sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

# Set permissions so non-root can read
sudo chmod 644 "$EVIDENCE_FILE"

echo "✅ Test evidence generated: $(stat -c%s "$EVIDENCE_FILE") bytes"
