#!/usr/bin/env python3
"""Aggregate runs2.csv -> per-file medians + corpus x codec CPU summary."""
import os
import csv, statistics, sys, collections

LANE = os.environ.get("APPLESAUCE_BENCH_OUT", os.path.dirname(os.path.abspath(__file__)))

def fnum(x):
    try: return float(x)
    except (TypeError, ValueError): return None

def med(v):
    v = [x for x in v if x is not None]
    return statistics.median(v) if v else None

def mn(v):
    v = [x for x in v if x is not None]
    return min(v) if v else None

def mx(v):
    v = [x for x in v if x is not None]
    return max(v) if v else None

rows = list(csv.DictReader(open(f"{LANE}/results/runs2.csv")))
seen = {}
for r in rows:
    seen[(r["corpus"], r["file"], r["codec"], r["path"], r["rep"])] = r
rows = list(seen.values())

g = collections.defaultdict(list)
for r in rows:
    g[(r["corpus"], r["file"], r["codec"], r["path"])].append(r)

per = {}
for (c_, f, codec, path), rs in sorted(g.items()):
    orig = int(rs[0]["orig_bytes"])
    def col(k, fn=med): return fn([fnum(r[k]) for r in rs])
    cb = col("comp_bytes")
    per[(c_, f, codec)] = dict(
        path=path, orig=orig, comp=cb,
        ratio=cb/orig if cb and orig else None,
        enc_cpu=col("enc_cpu_ns_per_b"), dec_cpu=col("dec_cpu_ns_per_b"),
        enc_cpu_min=col("enc_cpu_ns_per_b", mn), enc_cpu_max=col("enc_cpu_ns_per_b", mx),
        dec_cpu_min=col("dec_cpu_ns_per_b", mn), dec_cpu_max=col("dec_cpu_ns_per_b", mx),
        real=col("real_s"), d_real=col("d_real_s"),
        util=col("cpu_util"), d_util=col("d_cpu_util"),
        rss=col("rss_mb"), d_rss=col("d_rss_mb"),
        peak=col("peak_mem_mb"), d_peak=col("d_peak_mem_mb"),
        mbps=col("comp_mbps"), d_mbps=col("decomp_mbps"),
        status=",".join(sorted({r["status"] for r in rs})))

mode = sys.argv[1] if len(sys.argv) > 1 else "agg"
if mode == "agg":
    # corpus x codec: sum orig/sum comp; CPU s per GB = med enc_cpu*1e9/1e9 s/GB
    agg = collections.defaultdict(lambda: dict(orig=0, comp=0, enc=[], dec=[], mbps=[], dmbps=[], util=[], n=0))
    for (c_, f, codec), d in per.items():
        a = agg[(c_, codec)]
        a["n"] += 1; a["orig"] += d["orig"]
        if d["comp"] is not None: a["comp"] += d["comp"]
        for k, v in (("enc", d["enc_cpu"]), ("dec", d["dec_cpu"]),
                     ("mbps", d["mbps"]), ("dmbps", d["d_mbps"]), ("util", d["util"])):
            if v is not None: a[k].append(v)
    print(f"{'corpus':<11}{'codec':<9}{'n':>3} {'ratio':>7} {'encCPU s/GB':>11} {'decCPU s/GB':>11} {'cMB/s':>8} {'dMB/s':>8} {'util':>5}")
    for (c_, codec), a in sorted(agg.items()):
        r = a["comp"]/a["orig"] if a["orig"] else None
        e = med(a["enc"]); dd = med(a["dec"])
        print(f"{c_:<11}{codec:<9}{a['n']:>3} {r:.3f}   "
              f"{(e*1000/1000 if e else 0):>11.3f} {(dd*1000/1000 if dd else 0):>11.3f} "
              f"{med(a['mbps']) or 0:>8.1f} {med(a['dmbps']) or 0:>8.1f} {med(a['util']) or 0:>5.2f}")
elif mode == "files":
    print(f"{'file':<36}{'codec':<9}{'ratio':>7} {'encCPU':>7} {'e_min':>6} {'e_max':>6} {'decCPU':>7} {'util':>5} {'d_utl':>5} {'status'}")
    for (c_, f, codec), d in sorted(per.items()):
        ff = f"{c_}/{f}"
        p = lambda v: f"{v:.2f}" if v is not None else "-"
        print(f"{ff:<36}{codec:<9}{d['ratio'] or 0:>7.3f} {p(d['enc_cpu']):>7} {p(d['enc_cpu_min']):>6} {p(d['enc_cpu_max']):>6} {p(d['dec_cpu']):>7} {p(d['util']):>5} {p(d['d_util']):>5} {d['status']}")
elif mode == "csv":
    w = csv.writer(sys.stdout)
    w.writerow(["corpus","file","codec","path","orig","comp","ratio",
                "enc_cpu_ns_per_b","enc_cpu_min","enc_cpu_max",
                "dec_cpu_ns_per_b","dec_cpu_min","dec_cpu_max",
                "real_s","d_real_s","cpu_util","d_cpu_util",
                "rss_mb","d_rss_mb","peak_mem_mb","d_peak_mem_mb",
                "comp_mbps","decomp_mbps","status"])
    for (c_, f, codec), d in sorted(per.items()):
        w.writerow([c_, f, codec, d["path"], d["orig"],
                    int(d["comp"]) if d["comp"] is not None else "",
                    f"{d['ratio']:.4f}" if d["ratio"] else "",
                    d["enc_cpu"], d["enc_cpu_min"], d["enc_cpu_max"],
                    d["dec_cpu"], d["dec_cpu_min"], d["dec_cpu_max"],
                    d["real"], d["d_real"], d["util"], d["d_util"],
                    d["rss"], d["d_rss"], d["peak"], d["d_peak"],
                    d["mbps"], d["d_mbps"], d["status"]])
elif mode == "issues":
    for (c_, f, codec, path), rs in sorted(g.items()):
        bad = [r for r in rs if r["status"] not in ("ok", "skipped-ratio")]
        if bad or any(r["sha_ok"] in ("False", "0") for r in rs):
            print(c_, f, codec, ",".join(sorted({r["status"] for r in rs})),
                  "; ".join(r["note"] for r in rs if r["note"])[:200])
