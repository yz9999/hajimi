#!/usr/bin/env python3
"""Build the macOS icon from the supplied cat artwork using sips and iconutil."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
RESOURCES = ROOT / "Resources"
ICONSET = RESOURCES / "Hajimi.iconset"
SOURCE = RESOURCES / "Hajimi.png"
CANVAS_SIZE = 1024
ARTWORK_SIZE = 896


def main():
    if not SOURCE.is_file():
        raise SystemExit(f"Missing cat icon artwork: {SOURCE}")

    RESOURCES.mkdir(parents=True, exist_ok=True)
    specs = {
        "icon_16x16.png": 16,
        "icon_16x16@2x.png": 32,
        "icon_32x32.png": 32,
        "icon_32x32@2x.png": 64,
        "icon_128x128.png": 128,
        "icon_128x128@2x.png": 256,
        "icon_256x256.png": 256,
        "icon_256x256@2x.png": 512,
        "icon_512x512.png": 512,
        "icon_512x512@2x.png": 1024,
    }
    with tempfile.TemporaryDirectory(prefix="hajimi-icon-") as temporary:
        staging = Path(temporary)
        resized = staging / "resized.png"
        master = staging / "master.png"
        iconset = staging / "Hajimi.iconset"
        icns = staging / "Hajimi.icns"
        iconset.mkdir()

        # Preserve the complete illustration and its text, with transparent
        # padding instead of cropping or stretching the non-square source.
        subprocess.run(
            ["/usr/bin/sips", "--resampleHeightWidthMax", str(ARTWORK_SIZE),
             str(SOURCE), "--out", str(resized)],
            check=True, stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["/usr/bin/sips", "--padToHeightWidth", str(CANVAS_SIZE), str(CANVAS_SIZE),
             str(resized), "--out", str(master)],
            check=True, stdout=subprocess.DEVNULL,
        )
        for name, size in specs.items():
            subprocess.run(
                ["/usr/bin/sips", "-z", str(size), str(size), str(master),
                 "--out", str(iconset / name)],
                check=True, stdout=subprocess.DEVNULL,
            )
        subprocess.run(
            ["/usr/bin/iconutil", "-c", "icns", str(iconset), "-o", str(icns)],
            check=True,
        )

        # Do not replace existing generated assets until conversion succeeds.
        if ICONSET.exists():
            shutil.rmtree(ICONSET)
        shutil.copytree(iconset, ICONSET)
        shutil.copyfile(icns, RESOURCES / "Hajimi.icns")


if __name__ == "__main__":
    main()
