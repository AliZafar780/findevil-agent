#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# generate_ground_truth_image.sh
#
# Builds a 10MB ext2 disk image at /evidence/cases/ground_truth.raw
# containing *documented* ground-truth artefacts used by
# tests/test_ground_truth.py and scripts/run_accuracy_benchmark.py
# to score the FindEvil agent's detection accuracy.
#
# Requires sudo (for mkfs.ext2 + mount).  Safe to re-run: existing
# image and manifest are kept unless --force is passed.
#
# Usage:
#   sudo bash scripts/generate_ground_truth_image.sh [--force]
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

EVIDENCE_DIR="/evidence/cases"
IMAGE_PATH="${EVIDENCE_DIR}/ground_truth.raw"
MANIFEST_PATH="${EVIDENCE_DIR}/ground_truth_manifest.json"
IMAGE_SIZE_MB=10
FS_LABEL="GROUNDEVIL"

# ── CLI args ──────────────────────────────────────────────────────
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=1 ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: this script needs root (sudo) to mkfs.ext2 and mount." >&2
    exit 1
fi

run_root() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

mkdir -p "$EVIDENCE_DIR"

if [ -f "$IMAGE_PATH" ] && [ -f "$MANIFEST_PATH" ] && [ "$FORCE" -ne 1 ]; then
    SIZE=$(stat -c%s "$IMAGE_PATH" 2>/dev/null || echo 0)
    echo "Ground truth image already exists: $IMAGE_PATH ($SIZE bytes)"
    echo "Manifest: $MANIFEST_PATH"
    echo "Re-run with --force to regenerate."
    exit 0
fi

# ── Image creation ────────────────────────────────────────────────
echo "==> Creating ${IMAGE_SIZE_MB}MB sparse image at $IMAGE_PATH"
dd if=/dev/zero of="$IMAGE_PATH" bs=1M count=$IMAGE_SIZE_MB status=none

echo "==> Formatting ext2 with label '$FS_LABEL'"
run_root mkfs.ext2 -F -L "$FS_LABEL" "$IMAGE_PATH" >/dev/null

# ── Mount + plant artefacts ───────────────────────────────────────
MOUNT_POINT=$(mktemp -d)
echo "==> Mounting image at $MOUNT_POINT"
run_root mount -o loop,rw "$IMAGE_PATH" "$MOUNT_POINT"

# Plant directory
PLANT_DIR="$MOUNT_POINT/known_files"
run_root mkdir -p "$PLANT_DIR"
run_root chmod 755 "$PLANT_DIR"

echo "==> Planting artefacts"

# 1. Planted SECRET — should be detected by YARA / extract_features
SECRET_CONTENT="PLANTED_SECRET_MARKER_GT_001"
run_root bash -c "printf '%s\n' '$SECRET_CONTENT' > '$PLANT_DIR/secret.txt'"
SECRET_SHA=$(run_root sha256sum "$MOUNT_POINT/known_files/secret.txt" | awk '{print $1}')

# 2. Planted CREDENTIALS — should match user:password pattern
CRED_CONTENT="user:admin password:PLANTED_CRED_GT_002"
run_root bash -c "printf '%s\n' '$CRED_CONTENT' > '$PLANT_DIR/credentials.txt'"
CRED_SHA=$(run_root sha256sum "$MOUNT_POINT/known_files/credentials.txt" | awk '{print $1}')

# 3. Planted MALWARE signature (binary-ish; no trailing newline)
run_root bash -c "printf 'PLANTED_MALWARE_GT_003' > '$PLANT_DIR/suspicious.bin'"
MALWARE_SHA=$(run_root sha256sum "$MOUNT_POINT/known_files/suspicious.bin" | awk '{print $1}')

# 4. Control file — random-ish text; MUST NOT be flagged
NORMAL_CONTENT="This is a normal file with no malicious content. PLANTED_NORMAL_GT_004"
run_root bash -c "printf '%s\n' '$NORMAL_CONTENT' > '$PLANT_DIR/normal.txt'"
NORMAL_SHA=$(run_root sha256sum "$MOUNT_POINT/known_files/normal.txt" | awk '{print $1}')

# 5. Three DELETED files — should be carved from unallocated space.
#    We plant them, sync, then rm them before unmount.
for i in 1 2 3; do
    DEL_PATH="$PLANT_DIR/deleted_${i}.txt"
    run_root bash -c "printf 'DELETED_FILE_GT_D${i}_%s\n' '$(date +%s)' > '$DEL_PATH'"
done
# Sync and remove so the data is still in the image but inode is gone.
sync
run_root rm -f "$PLANT_DIR"/deleted_*.txt

# 6. SUID binary — should be flagged by an agent that inspects modes
SUID_PATH="$PLANT_DIR/suid_binary"
run_root bash -c "printf '#!/bin/sh\necho GT_SUID_SCRIPT_GT_006\n' > '$SUID_PATH'"
run_root chmod 4755 "$SUID_PATH"
SUID_MODE=$(run_root stat -c '%a' "$SUID_PATH")

# Sync before unmount so all writes hit the image.
sync

# ── Unmount ───────────────────────────────────────────────────────
echo "==> Unmounting image"
run_root umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

# ── Write the manifest ────────────────────────────────────────────
echo "==> Writing ground truth manifest"
cat > "$MANIFEST_PATH" <<EOF
{
  "image": "${IMAGE_PATH}",
  "image_size_bytes": $((IMAGE_SIZE_MB * 1024 * 1024)),
  "filesystem": "ext2",
  "label": "${FS_LABEL}",
  "created_by": "scripts/generate_ground_truth_image.sh",
  "expected_findings": {
    "known_files": [
      {
        "path": "/known_files/secret.txt",
        "type": "secret",
        "content_marker": "${SECRET_CONTENT}",
        "sha256": "${SECRET_SHA}",
        "should_be_detected": true,
        "detection_methods": ["scan_yara", "extract_features", "fs_extract_file"]
      },
      {
        "path": "/known_files/credentials.txt",
        "type": "credentials",
        "content_marker": "${CRED_CONTENT}",
        "sha256": "${CRED_SHA}",
        "should_be_detected": true,
        "detection_methods": ["scan_yara", "extract_features"]
      },
      {
        "path": "/known_files/suspicious.bin",
        "type": "suspicious_binary",
        "content_marker": "PLANTED_MALWARE_GT_003",
        "sha256": "${MALWARE_SHA}",
        "should_be_detected": true,
        "detection_methods": ["scan_yara", "fs_extract_file"]
      }
    ],
    "deleted_files": [
      {
        "path": "/known_files/deleted_1.txt",
        "content_marker": "DELETED_FILE_GT_D1",
        "should_be_carved": true
      },
      {
        "path": "/known_files/deleted_2.txt",
        "content_marker": "DELETED_FILE_GT_D2",
        "should_be_carved": true
      },
      {
        "path": "/known_files/deleted_3.txt",
        "content_marker": "DELETED_FILE_GT_D3",
        "should_be_carved": true
      }
    ],
    "suid_files": [
      {
        "path": "/known_files/suid_binary",
        "permissions": "${SUID_MODE}",
        "should_be_flagged": true
      }
    ],
    "false_positive_files": [
      {
        "path": "/known_files/normal.txt",
        "content_marker": "PLANTED_NORMAL_GT_004",
        "sha256": "${NORMAL_SHA}",
        "should_not_be_detected_as_malware": true
      }
    ]
  },
  "agent_invocation": {
    "phases": [
      "initial_triage",
      "filesystem_analysis",
      "artifact_extraction"
    ],
    "expected_tool_calls": [
      "list_evidence",
      "fs_list_files",
      "verify_hash",
      "carve_files",
      "scan_yara",
      "extract_features"
    ],
    "min_findings": 5
  }
}
EOF

# Ensure the image is readable by the test process (which may run as
# a non-root user when invoked from pytest).
chmod 644 "$IMAGE_PATH" 2>/dev/null || run_root chmod 644 "$IMAGE_PATH"
chmod 644 "$MANIFEST_PATH" 2>/dev/null || run_root chmod 644 "$MANIFEST_PATH"

echo
echo "✅ Ground truth image generated:"
echo "   image:    $IMAGE_PATH ($(stat -c%s "$IMAGE_PATH") bytes)"
echo "   manifest: $MANIFEST_PATH"
echo
echo "Plant summary:"
echo "  - 3 known_files (secret, credentials, suspicious binary)"
echo "  - 3 deleted_files (carve test)"
echo "  - 1 SUID binary"
echo "  - 1 control file (must NOT trigger malware detection)"
echo
echo "Verify with:"
echo "  python -m pytest tests/test_ground_truth.py -v"
