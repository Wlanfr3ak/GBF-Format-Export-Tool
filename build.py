#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build gbf_extract into a single-file Windows .exe via PyInstaller.

Output name always contains the version:
    dist/GBF-Extract_v<VERSION>.exe
"""
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "src" / "gbf_extract.py"


def stage_tcl_data():
    """Python 3.15 ships Tcl/Tk 9 as zip archives under <prefix>/tcl
    (libtcl9.x.y.zip -> tcl_library/, libtk9.x.y.zip -> tk_library/).
    PyInstaller's tkinter runtime hook expects extracted script dirs at
    sys._MEIPASS/_tcl_data and _tk_data, so unpack them into a staging dir
    and ship them via --add-data."""
    tcl_root = Path(sys.base_prefix) / "tcl"
    staging = ROOT / "build" / "tcl_stage"
    for zip_pat, member_root, dest in (
            ("libtcl*.zip", "tcl_library", "_tcl_data"),
            ("libtk*.zip", "tk_library", "_tk_data")):
        zips = sorted(tcl_root.glob(zip_pat))
        if not zips:
            continue
        target = staging / dest
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zips[-1]) as z:
            for n in z.namelist():
                if n.startswith(member_root + "/") and not n.endswith("/"):
                    out = target / n[len(member_root) + 1:]
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(z.read(n))
    return staging


def get_version():
    m = re.search(r'__version__\s*=\s*"([^"]+)"', SRC.read_text())
    if not m:
        sys.exit("could not find __version__ in " + str(SRC))
    return m.group(1)


def main():
    ver = get_version()
    name = f"GBF-Extract_v{ver}"
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--console",
        "--name", name,
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT),
        "--clean",
        "--hidden-import", "_tkinter",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinterdnd2",
        "--collect-all", "tkinterdnd2",
        "--collect-all", "av",
        "--collect-all", "PIL",
        "--hidden-import", "fpdf",
    ]
    staging = stage_tcl_data()
    if (staging / "_tcl_data").is_dir():
        cmd += ["--add-data", f"{staging / '_tcl_data'};_tcl_data",
                "--add-data", f"{staging / '_tk_data'};_tk_data"]
    cmd += [
        str(SRC),
    ]
    print("building", name, "...")
    r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit(r.returncode)
    print(f"done: dist/{name}.exe")


if __name__ == "__main__":
    main()
