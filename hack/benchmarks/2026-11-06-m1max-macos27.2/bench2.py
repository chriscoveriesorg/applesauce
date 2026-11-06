#!/usr/bin/env python3
"""Applesauce precise benchmark harness v2 — CPU-time edition.

Same file x codec matrix as bench.py, plus per-run user/sys CPU seconds,
instructions retired, cycles elapsed, peak memory footprint, and CPU
utilisation ((user+sys)/real) from /usr/bin/time -l.
Batch header rows record load average, thermal and power state.
"""
import csv, hashlib, os, re, shutil, subprocess, sys, time

BIN = os.environ.get("APPLESAUCE_BIN", "target/release/applesauce")
LANE = os.environ.get("APPLESAUCE_BENCH_OUT", os.path.dirname(os.path.abspath(__file__)))
WORK = f"{LANE}/work"
DATA = os.environ.get("APPLESAUCE_BENCH_DATA", "bench-data")
CSV_PATH = f"{LANE}/results/runs2.csv"
BATCH_LOG = f"{LANE}/results/batches.log"
TIMEOUT = 1200

FIELDS = ["batch","corpus","file","orig_bytes","codec","path","rep","status",
          "real_s","user_s","sys_s","cpu_util","instr_m","cycles_m",
          "rss_mb","peak_mem_mb",
          "d_real_s","d_user_s","d_sys_s","d_cpu_util","d_instr_m","d_cycles_m",
          "d_rss_mb","d_peak_mem_mb",
          "verify_s","comp_bytes","ratio",
          "comp_mbps","decomp_mbps","enc_cpu_ns_per_b","dec_cpu_ns_per_b",
          "sha_ok","note"]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def run_timed(cmd, stdout_to=None):
    """Run under /usr/bin/time -l; return dict of metrics + rc + stderr."""
    full = ["/usr/bin/time", "-l"] + cmd
    t0 = time.monotonic()
    if stdout_to:
        with open(stdout_to, "wb") as out:
            p = subprocess.run(full, stdout=out, stderr=subprocess.PIPE, timeout=TIMEOUT)
    else:
        p = subprocess.run(full, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, timeout=TIMEOUT)
    wall_fallback = time.monotonic() - t0
    err = p.stderr.decode("utf-8", "replace")
    def f(pat, cast=float):
        m = re.search(pat, err)
        return cast(m.group(1)) if m else None
    real = f(r"([\d.]+)\s+real\s+[\d.]+\s+user") or wall_fallback
    m = re.search(r"([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys", err)
    user = float(m.group(2)) if m else None
    sys_ = float(m.group(3)) if m else None
    cmd_err = err[:re.search(r"^\s*[\d.]+\s+real\s", err, re.M).start()] \
        if re.search(r"^\s*[\d.]+\s+real\s", err, re.M) else err
    return {
        "real": real, "user": user, "sys": sys_, "rc": p.returncode,
        "rss": f(r"(\d+)\s+maximum resident set size", int),
        "instr": f(r"(\d+)\s+instructions retired", int),
        "cycles": f(r"(\d+)\s+cycles elapsed", int),
        "peak": f(r"(\d+)\s+peak memory footprint", int),
        "err": cmd_err.strip()[-200:],
    }

def metrics(d, prefix, row):
    row[f"{prefix}real_s"] = f"{d['real']:.4f}" if d["real"] is not None else ""
    row[f"{prefix}user_s"] = f"{d['user']:.4f}" if d["user"] is not None else ""
    row[f"{prefix}sys_s"] = f"{d['sys']:.4f}" if d["sys"] is not None else ""
    if d["user"] is not None and d["sys"] is not None and d["real"]:
        row[f"{prefix}cpu_util"] = f"{(d['user']+d['sys'])/d['real']:.3f}"
    row[f"{prefix}instr_m"] = f"{d['instr']/1e6:.1f}" if d["instr"] else ""
    row[f"{prefix}cycles_m"] = f"{d['cycles']/1e6:.1f}" if d["cycles"] else ""
    row[f"{prefix}rss_mb"] = f"{d['rss']/1e6:.1f}" if d["rss"] else ""
    row[f"{prefix}peak_mem_mb"] = f"{d['peak']/1e6:.1f}" if d["peak"] else ""

def warm(path):
    with open(path, "rb") as f:
        while f.read(1 << 22):
            pass

def decmpfs_size(path):
    """Require a successful, parseable native compression report.

    An info command failure or missing size must never produce an apparently
    successful native-codec benchmark row with a blank compression ratio.
    """
    p = subprocess.run([BIN, "info", path], capture_output=True, text=True,
                       timeout=TIMEOUT)
    if p.returncode:
        raise RuntimeError(
            f"applesauce info failed (rc={p.returncode}): {p.stderr.strip()[-160:]}")
    if "is not compressed" in p.stdout:
        return None, False, "not-compressed"
    m = re.search(r"Compressed size:\s*(\d+)\b", p.stdout)
    if not m or int(m.group(1)) <= 0:
        raise RuntimeError("applesauce info returned no valid compressed byte count")
    return int(m.group(1)), True, ""

def batch_header(tag):
    up = subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()
    batt = subprocess.run(["pmset", "-g", "batt"], capture_output=True,
                          text=True).stdout.strip().splitlines()[-1]
    therm = subprocess.run(["pmset", "-g", "therm"], capture_output=True,
                           text=True).stdout.strip().replace("\n", " | ")
    line = f"{time.strftime('%H:%M:%S')} [{tag}] {up} | {batt} | {therm}\n"
    with open(BATCH_LOG, "a") as fh:
        fh.write(line)
    print(line, end="", flush=True)

def bench_file(batch, corpus, path, codecs, reps_map, writer, fh):
    name = os.path.basename(path)
    orig = os.path.getsize(path)
    src_sha = sha256(path)
    for codec, kind in codecs:
        reps = reps_map.get(codec, reps_map.get("*", 3))
        if codec == "brotli" and orig > 8 * 1024 * 1024:
            reps = min(reps, 1)
        if reps <= 0:
            continue
        warm(path)
        for rep in range(1, reps + 1):
            row = dict.fromkeys(FIELDS, "")
            row.update(batch=batch, corpus=corpus, file=name,
                       orig_bytes=orig, codec=codec, path=kind, rep=rep)
            note = []
            try:
                if kind == "archive":
                    outp = f"{WORK}/{name}.{codec}.ascf"
                    rest = f"{WORK}/{name}.{codec}.rest"
                    for f_ in (outp, rest):
                        if os.path.exists(f_):
                            os.remove(f_)
                    d = run_timed([BIN, "archive", "create", path, outp,
                                   "--codec", codec, "--allow-expansion"])
                    metrics(d, "", row)
                    if d["rc"] != 0:
                        row["status"] = "error"; note.append(f"create rc={d['rc']}: {d['err']}")
                    else:
                        row["comp_bytes"] = os.path.getsize(outp)
                        dv = run_timed([BIN, "archive", "verify", outp])
                        row["verify_s"] = f"{dv['real']:.4f}"
                        if dv["rc"] != 0:
                            row["status"] = "error"
                            note.append(f"verify rc={dv['rc']}: {dv['err']}")
                        d = run_timed([BIN, "archive", "extract", outp, rest])
                        metrics(d, "d_", row)
                        if d["rc"] != 0:
                            row["status"] = "error"; note.append(f"extract rc={d['rc']}: {d['err']}")
                        else:
                            ok = sha256(rest) == src_sha
                            row["sha_ok"] = ok
                            if not ok:
                                row["status"] = "SHA-MISMATCH"
                elif kind == "decmpfs":
                    copy = f"{WORK}/{name}.native"
                    shutil.copyfile(path, copy)
                    d = run_timed([BIN, "compress", "-q", "-c", codec, copy])
                    metrics(d, "", row)
                    if d["rc"] != 0:
                        row["status"] = "error"; note.append(f"compress rc={d['rc']}: {d['err']}")
                    else:
                        csize, is_comp, inote = decmpfs_size(copy)
                        if not is_comp:
                            row["comp_bytes"] = orig
                            row["status"] = "skipped-ratio"; note.append(inote)
                            row["sha_ok"] = sha256(copy) == src_sha
                            if not row["sha_ok"]:
                                row["status"] = "SHA-MISMATCH"
                        else:
                            row["comp_bytes"] = csize
                            d = run_timed([BIN, "decompress", "-q", copy])
                            metrics(d, "d_", row)
                            if d["rc"] != 0:
                                row["status"] = "error"; note.append(f"decompress rc={d['rc']}: {d['err']}")
                            else:
                                ok = sha256(copy) == src_sha
                                row["sha_ok"] = ok
                                if not ok:
                                    row["status"] = "SHA-MISMATCH"
                else:
                    ccmd, dcmd = STREAMS[codec]
                    outp = f"{WORK}/{name}.{codec}.z"
                    rest = f"{WORK}/{name}.{codec}.rest"
                    for f_ in (outp, rest):
                        if os.path.exists(f_):
                            os.remove(f_)
                    d = run_timed(ccmd(path), stdout_to=outp)
                    metrics(d, "", row)
                    if d["rc"] != 0:
                        row["status"] = "error"; note.append(f"compress rc={d['rc']}: {d['err']}")
                    else:
                        row["comp_bytes"] = os.path.getsize(outp)
                        d = run_timed(dcmd(outp), stdout_to=rest)
                        metrics(d, "d_", row)
                        if d["rc"] != 0:
                            row["status"] = "error"; note.append(f"decompress rc={d['rc']}: {d['err']}")
                        else:
                            ok = sha256(rest) == src_sha
                            row["sha_ok"] = ok
                            if not ok:
                                row["status"] = "SHA-MISMATCH"
            except subprocess.TimeoutExpired:
                row["status"] = "timeout"; note.append(f">{TIMEOUT}s")
            except Exception as e:
                row["status"] = "harness-error"; note.append(repr(e)[:200])
            if not row["status"]:
                row["status"] = "ok"
            cb = row["comp_bytes"]
            if cb not in ("", None) and row.get("real_s") and orig > 0:
                row["ratio"] = f"{cb/orig:.4f}"
                cs = float(row["real_s"])
                ds = float(row.get("d_real_s") or 0)
                row["comp_mbps"] = f"{orig/cs/1e6:.1f}" if cs > 0 else ""
                row["decomp_mbps"] = f"{orig/ds/1e6:.1f}" if ds > 0 else ""
                # CPU seconds per input byte (user+sys), the load-independent speed metric
                if row.get("user_s") and row.get("sys_s"):
                    row["enc_cpu_ns_per_b"] = f"{(float(row['user_s'])+float(row['sys_s']))*1e9/orig:.2f}"
                if row.get("d_user_s") and row.get("d_sys_s"):
                    row["dec_cpu_ns_per_b"] = f"{(float(row['d_user_s'])+float(row['d_sys_s']))*1e9/orig:.2f}"
            row["note"] = "; ".join(n for n in note if n)
            writer.writerow(row)
            fh.flush()
            if row["status"] == "SHA-MISMATCH":
                print(f"P0 SHA MISMATCH {corpus}/{name} {codec}", flush=True)

STREAMS = {
    "zstd":  (lambda s: ["zstd", "-q", "-c", s],  lambda o: ["zstd", "-q", "-d", "-c", o]),
    "xz":    (lambda s: ["xz", "-c", s],          lambda o: ["xz", "-d", "-c", o]),
    "brotli":(lambda s: ["brotli", "-c", s],      lambda o: ["brotli", "-d", "-c", o]),
    "lz4":   (lambda s: ["lz4", "-q", "-c", s],   lambda o: ["lz4", "-d", "-c", o]),
    "gzip":  (lambda s: ["gzip", "-c", s],        lambda o: ["gzip", "-d", "-c", o]),
    "bzip2": (lambda s: ["bzip2", "-c", s],       lambda o: ["bzip2", "-d", "-c", o]),
}

CODECS_MAIN = (
    [("lzraven", "archive"), ("lzmesh", "archive")]
    + [(c, "decmpfs") for c in ("lzfse", "lzvn", "zlib", "lzbitmap")]
    + [(c, "stream") for c in STREAMS]
)

def files_in(d):
    return sorted(os.path.join(d, f) for f in os.listdir(d)
                  if os.path.isfile(os.path.join(d, f)))

def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "main"
    if which not in ("main", "edge", "big4g"):
        raise ValueError(f"unknown benchmark batch: {which!r}")
    if not os.path.isdir(DATA):
        raise FileNotFoundError(f"benchmark data root does not exist: {DATA}")
    required = (("canterbury", "large", "silesia", "enwik8", "synthetic")
                if which == "main" else ("edge",))
    for corpus in required:
        corpus_dir = os.path.join(DATA, corpus)
        if not os.path.isdir(corpus_dir):
            raise FileNotFoundError(f"benchmark corpus directory does not exist: {corpus_dir}")
    if which in ("edge", "big4g"):
        names = (("big-4g.bin",) if which == "big4g" else
                 ("empty.bin", "one.bin", "exact-64k.bin", "64k-plus-1.bin",
                  "random-64m.bin"))
        for name in names:
            input_path = os.path.join(DATA, "edge", name)
            if not os.path.isfile(input_path):
                raise FileNotFoundError(f"benchmark input file does not exist: {input_path}")
            if os.path.islink(input_path):
                raise ValueError(f"benchmark input must not be a symlink: {input_path}")
    if which == "main":
        for corpus in required:
            corpus_dir = os.path.join(DATA, corpus)
            inputs = files_in(corpus_dir)
            if not inputs:
                raise ValueError(f"benchmark corpus has no input files: {corpus_dir}")
            for input_path in inputs:
                if os.path.islink(input_path):
                    raise ValueError(f"benchmark input must not be a symlink: {input_path}")
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    write_header = not os.path.exists(CSV_PATH)
    fh = open(CSV_PATH, "a", newline="")
    writer = csv.DictWriter(fh, fieldnames=FIELDS)
    if write_header:
        writer.writeheader()
    if which == "main":
        corpora = {
            "canterbury": files_in(f"{DATA}/canterbury"),
            "large": files_in(f"{DATA}/large"),
            "silesia": files_in(f"{DATA}/silesia"),
            "enwik8": files_in(f"{DATA}/enwik8"),
            "synthetic": files_in(f"{DATA}/synthetic"),
        }
        for corpus, files in corpora.items():
            batch_header(f"batch:{corpus}")
            for path in files:
                print(f"[{time.strftime('%H:%M:%S')}] {corpus}/{os.path.basename(path)}", flush=True)
                bench_file(f"batch:{corpus}", corpus, path, CODECS_MAIN, {"*": 3}, writer, fh)
    elif which == "edge":
        batch_header("batch:edge")
        edge = [f"{DATA}/edge/{n}" for n in
                ("empty.bin", "one.bin", "exact-64k.bin", "64k-plus-1.bin",
                 "random-64m.bin")]
        for path in edge:
            bench_file("batch:edge", "edge", path, CODECS_MAIN, {"*": 3}, writer, fh)
    elif which == "big4g":
        batch_header("batch:big4g")
        path = f"{DATA}/edge/big-4g.bin"
        codecs = ([("lzraven", "archive"), ("lzmesh", "archive")]
                  + [(c, "stream") for c in ("zstd", "lz4")])
        bench_file("batch:big4g", "edge", path, codecs,
                   {"lzraven": 1, "lzmesh": 2, "zstd": 1, "lz4": 1}, writer, fh)
    fh.close()

if __name__ == "__main__":
    main()
