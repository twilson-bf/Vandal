#!/usr/bin/env python3
"""Copy locally supplied Lotus fonts into ignored static assets; no redistribution."""
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('MarathonShapiro_Wide65.woff2', 'Shapiro_55Middle.woff2',
         'KHInterference_Regular.woff2', 'PPFraktionMono_Regular.woff2',
         'PPFraktionMono_Medium.woff2', 'NIS-JTC-Win-M9.ttf')


def main():
    source = Path(sys.argv[1] if len(sys.argv) > 1 else os.getenv('VANDAL_FONTS_DIR', str(ROOT.parent / 'lotus-fonts'))).expanduser()
    if (source / 'fonts').is_dir():
        source = source / 'fonts'
    if not source.is_dir():
        print('Lotus fonts not found; bundled open-font fallbacks remain available.')
        return
    destination = ROOT / 'vandal/static/fonts/local'
    destination.mkdir(parents=True, exist_ok=True)
    for name in NAMES:
        src, dst = source / name, destination / name
        if not src.is_file():
            print(f'MISSING local font: {name}')
        elif dst.exists() and dst.read_bytes() == src.read_bytes():
            print(f'OK   font {name} (unchanged)')
        else:
            staging = dst.with_suffix(dst.suffix + '.tmp')
            shutil.copyfile(src, staging)
            staging.replace(dst)
            print(f'COPY font {name}')


if __name__ == '__main__':
    main()
