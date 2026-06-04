#!/bin/bash
set -euo pipefail

echo "╔══════════════════════════════════════════════════╗"
echo "║     FIND EVIL! — Autonomous DFIR Agent Setup    ║"
echo "╚══════════════════════════════════════════════════╝"

# ── Check SIFT Workstation ────────────────────────────────────────
echo ""
echo "[1/4] Checking SIFT Workstation..."
SIFT_TOOLS=(fls icat mmls fsstat foremost bulk_extractor tshark yara hashdeep strings)
MISSING=()
for tool in "${SIFT_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "  [✓] $tool found at $(which "$tool")"
    else
        echo "  [✗] $tool NOT found"
        MISSING+=("$tool")
    fi
done

if [ ${#MISSING[@]} -gt 5 ]; then
    echo ""
    echo "[!] SIFT Workstation not fully installed."
    echo "    Install via Docker:"
    echo "    docker pull sansdfir/sift"
    echo "    docker run --rm -it -v /cases:/cases sansdfir/sift /bin/bash"
    echo ""
    echo "    Or native:"
    echo "    curl -L https://raw.githubusercontent.com/teamdfir/sift-saltstack/master/bootstrap.sh | sudo bash"
    echo ""
    read -p "    Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# ── Python Virtual Environment ────────────────────────────────────
echo ""
echo "[2/4] Setting up Python environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "  [✓] Virtual environment created"
fi
source venv/bin/activate
echo "  [✓] Virtual environment activated"

pip install -q --upgrade pip
pip install -q -e ".[dev]"
pip install -q volatility3 regipy
echo "  [✓] Dependencies + extras (volatility3, regipy) installed"

# ── Evidence & Results Directories ────────────────────────────────
echo ""
echo "[3/4] Creating evidence directories..."
sudo mkdir -p /evidence/{disk,memory,network,cases}
sudo mkdir -p /results/{audit,carved,timelines,reports}
sudo chmod -R 755 /evidence /results
echo "  [✓] /evidence and /results directories ready"

# ── Download Test Data ─────────────────────────────────────────────
echo ""
echo "[4/4] Downloading test data..."
if [ ! -f /evidence/cases/nist-test-image.raw ]; then
    echo "  [.] Skipping NIST download (large file)."
    echo "  [.] Create a minimal test image:"
    echo "    dd if=/dev/zero of=/evidence/cases/test.raw bs=1M count=100"
    echo "    mkfs.ext2 /evidence/cases/test.raw"
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     SETUP COMPLETE                               ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Next steps:                                     ║"
echo "║  1. source venv/bin/activate                     ║"
echo "║  2. python -m src.server                         ║"
echo "║  3. Connect Claude Code:                         ║"
echo "║     claude mcp add findevil -e 'python -m src.server' ║"
echo "╚══════════════════════════════════════════════════╝"
