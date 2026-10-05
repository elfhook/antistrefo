#!/usr/bin/env python3
# quality.py - runs the quality scoreboard over a corpus and prints the table.
# Module: tool (Python 3).
# Owns: corpus collection, the analyze driver, and the baseline record.
# Depends: the antistrefo analyze JSON. stdlib only, no network, no installs.

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys

# The system images every Windows machine has, which is what makes the corpus
# reproducible rather than something that depends on files nobody can fetch.
SYSTEM_BIN = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")
CLEAN_SOURCES = [
    (os.path.join(SYSTEM_BIN, "ntdll.dll"), "ntdll"),
    (os.path.join(SYSTEM_BIN, "kernelbase.dll"), "kernelbase"),
    (os.path.join(SYSTEM_BIN, "user32.dll"), "user32"),
    (os.path.join(SYSTEM_BIN, "drivers", "ntfs.sys"), "ntfs"),
    (os.path.join(SYSTEM_BIN, "drivers", "storport.sys"), "storport"),
]


def find_exe(root, override):
    if override:
        return override
    hits = sorted(glob.glob(os.path.join(root, "build", "*", "bin", "antistrefo.exe")))
    return hits[-1] if hits else None


def find_extra(root):
    """The build's own binary, plus anything the caller dropped into corpus/extra."""
    out = []
    exe = find_exe(root, None)
    if exe:
        out.append((exe, "antistrefo"))
    extra = os.path.join(root, "corpus", "extra")
    if os.path.isdir(extra):
        for p in sorted(glob.glob(os.path.join(extra, "*"))):
            out.append((p, os.path.splitext(os.path.basename(p))[0]))
    return out


def collect_corpus(root, work):
    os.makedirs(work, exist_ok=True)
    files = []
    for src, name in CLEAN_SOURCES + find_extra(root):
        if not os.path.isfile(src):
            print(f"skip {name}: {src} not found", file=sys.stderr)
            continue
        dst = os.path.join(work, os.path.basename(src))
        if not os.path.exists(dst):
            shutil.copyfile(src, dst)
        files.append((name, dst))
    return files


def find_quality(obj):
    if isinstance(obj, dict):
        if "quality" in obj and isinstance(obj["quality"], dict):
            return obj["quality"]
        for v in obj.values():
            hit = find_quality(v)
            if hit:
                return hit
    elif isinstance(obj, list):
        for v in obj:
            hit = find_quality(v)
            if hit:
                return hit
    return None


def run_one(exe, path):
    proc = subprocess.run([exe, "analyze", path], capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        return None, f"exit {proc.returncode}"
    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return None, f"bad json: {e}"
    q = find_quality(body)
    if not q:
        return None, "no quality object"
    return q, None


def main():
    ap = argparse.ArgumentParser(description="run the quality scoreboard over the corpus")
    ap.add_argument("--root", default=".")
    ap.add_argument("--exe", default=None)
    ap.add_argument("--work", default=None)
    ap.add_argument("--save", default=None, help="write the baseline table here as JSON")
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    exe = find_exe(root, args.exe)
    if not exe:
        print("antistrefo.exe not found; build first", file=sys.stderr)
        return 2
    work = args.work or os.path.join(root, "build", "quality")
    files = collect_corpus(root, work)
    if not files:
        print("empty corpus", file=sys.stderr)
        return 2
    rows = []
    failed = 0
    for name, path in files:
        q, err = run_one(exe, path)
        if err:
            print(f"FAIL {name}: {err}", file=sys.stderr)
            failed += 1
            continue
        q["name"] = name
        rows.append(q)
    widths = max(len(r["name"]) for r in rows)
    print(f"{'file'.ljust(widths)}  score  funcs  pdata  hit  edges  ok  calls  named  "
          f"insns  low  indir  ok")
    for r in rows:
        print(
            f"{r['name'].ljust(widths)}  {r['score']:5.1f}  {r['funcs']:5d}  {r['pdata']:5d}  "
            f"{r['pdata_hit']:3d}  {r['edges']:5d}  {r['edges_resolved']:3d}  "
            f"{r['calls']:5d}  {r['calls_named']:5d}  {r['insns_sampled']:5d}  "
            f"{r['insns_lowered']:4d}  {r['indirect']:5d}  {r['indirect_resolved']:3d}")
    if rows:
        mean = sum(r["score"] for r in rows) / len(rows)
        print(f"\ncorpus mean score: {mean:.2f} over {len(rows)} files "
              f"({failed} failed)")
    if args.save:
        os.makedirs(os.path.dirname(os.path.abspath(args.save)), exist_ok=True)
        with open(args.save, "w", encoding="ascii") as fh:
            json.dump(rows, fh, indent=1)
            fh.write("\n")
        print(f"baseline written to {args.save}")
    return 1 if failed and not rows else 0


if __name__ == "__main__":
    sys.exit(main())
