#!/usr/bin/env python3
"""
Generate professional PNG renders of the FindEvil architecture diagram
and ASCII art assets for README/social media.

Requirements: pip install cairosvg pillow
Optional:     pip install svglib (converts SVG→PNG with Cairo)
"""

import sys
import subprocess
from pathlib import Path

HERE = Path(__file__).parent
SVG_PATH = HERE / "architecture.svg"
PNG_PATH = HERE / "architecture.png"
ARCHITECTURE_PNG = HERE / "findevil-architecture.png"


def generate_png_via_cairosvg():
    """Use cairosvg for direct SVG→PNG conversion."""
    try:
        import cairosvg
    except ImportError:
        return None

    cairosvg.svg2png(
        url=str(SVG_PATH),
        write_to=str(PNG_PATH),
        output_width=2560,
        output_height=1800,
        scale=2.0,
    )
    return PNG_PATH


def generate_png_via_inkscape():
    """Use Inkscape command-line for SVG→PNG."""
    inkscape = (
        "inkscape",
        "/usr/bin/inkscape",
        "/snap/bin/inkscape",
    )
    for exe in inkscape:
        try:
            subprocess.run(
                [exe, "--version"],
                capture_output=True,
            )
            subprocess.run(
                [
                    exe,
                    str(SVG_PATH),
                    "--export-type=png",
                    "--export-filename=" + str(PNG_PATH),
                    "--export-width=2560",
                    "--export-height=1800",
                    "--export-background=#0f172a",
                ],
                check=True,
            )
            return PNG_PATH
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    return None


def generate_png_via_pillow_svg():
    """Fallback: use Pillow with tiny wrapper."""
    try:
        from PIL import Image
        # Minimal SVG rendering via cairosvg or rsvg
        import cairosvg
        import io

        png_data = cairosvg.svg2png(
            url=str(SVG_PATH),
            output_width=2560,
            output_height=1800,
            scale=2.0,
        )
        with open(PNG_PATH, "wb") as f:
            f.write(png_data)
        return PNG_PATH
    except ImportError:
        return None


def main():
    print("🎨 Generating FindEvil architecture PNG...")

    # Try methods in order of quality
    methods = [
        ("cairosvg", generate_png_via_cairosvg),
        ("Inkscape", generate_png_via_inkscape),
        ("Pillow+SVG", generate_png_via_pillow_svg),
    ]

    for name, method in methods:
        try:
            result = method()
            if result:
                size = result.stat().st_size
                print(f"✅ {name}: {result} ({size:,} bytes)")
                # Copy to README location
                import shutil
                shutil.copy2(result, ARCHITECTURE_PNG)
                print(f"✅ Also saved: {ARCHITECTURE_PNG}")
                return
        except Exception as e:
            print(f"⚠️  {name} failed: {e}")

    print("❌ Could not generate PNG. Install cairosvg:")
    print("   pip install cairosvg")
    print("\n   The SVG file is at: docs/architecture.svg")
    print("   It can be viewed in any browser or converted manually.")
    sys.exit(1)


if __name__ == "__main__":
    main()
