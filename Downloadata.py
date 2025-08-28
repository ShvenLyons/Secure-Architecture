import argparse
import os
import sys
import shutil
import tempfile
import subprocess
from pathlib import Path
from fnmatch import fnmatch

FOLDER_URL = "https://drive.google.com/drive/folders/121wGPx9u7dQ8q5o9SfIbi1vkl__qh-6Q?usp=sharing"

def ensure_gdown():
    try:
        import gdown  # noqa: F401
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "gdown"])

def download_all(tmp_dir: Path):
    import gdown
    gdown.download_folder(
        url=FOLDER_URL,
        output=str(tmp_dir),
        quiet=False,
        use_cookies=True,
        remaining_ok=True
    )
    subs = [p for p in tmp_dir.iterdir() if p.is_dir()]
    if len(subs) == 1 and subs[0].name != tmp_dir.name:
        root = subs[0]
    else:
        root = tmp_dir
    return root

def copy_selected(src_root: Path, dst_root: Path, patterns):
    dst_root.mkdir(parents=True, exist_ok=True)
    matched_any = False
    for entry in src_root.iterdir():
        name = entry.name
        if any(fnmatch(name, pat) for pat in patterns):
            matched_any = True
            target = dst_root / name
            if entry.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(entry, target)
            else:
                shutil.copy2(entry, target)
    if not matched_any:
        for root, dirs, files in os.walk(src_root):
            root_path = Path(root)
            for d in list(dirs):
                full = root_path / d
                rel = full.relative_to(src_root)
                if any(fnmatch(str(rel).replace("\\", "/"), pat) for pat in patterns):
                    target = dst_root / rel
                    if target.exists():
                        shutil.rmtree(target)
                    shutil.copytree(full, target)
            for f in files:
                full = root_path / f
                rel = full.relative_to(src_root)
                if any(fnmatch(str(rel).replace("\\", "/"), pat) for pat in patterns):
                    target = dst_root / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(full, target)

def copy_all(src_root: Path, dst_root: Path):
    if dst_root.exists():
        pass
    dst_root.mkdir(parents=True, exist_ok=True)
    for entry in src_root.iterdir():
        target = dst_root / entry.name
        if entry.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(entry, target)
        else:
            shutil.copy2(entry, target)

def main():
    parser = argparse.ArgumentParser(description="Download dataset from Google Drive folder.")
    parser.add_argument("-o", "--output", default="dataset", help="Target directory (default: ./dataset)")
    parser.add_argument("--only", nargs="+",
                        help="Download only specific files/folders (wildcards supported).")
    args = parser.parse_args()

    ensure_gdown()

    outdir = Path(args.output).resolve()
    with tempfile.TemporaryDirectory(prefix="gdrive_fetch_") as td:
        tmp_dir = Path(td)
        src_root = download_all(tmp_dir)

        if args.only:
            copy_selected(src_root, outdir, args.only)
        else:
            copy_all(src_root, outdir)

if __name__ == "__main__":
    main()
