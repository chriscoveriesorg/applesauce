#!/usr/bin/env python3
"""Aggregate runs.csv -> per-file medians + per-corpus codec summaries."""
import os
import csv, statistics, sys, collections

LANE = os.environ.get("APPLESAUCE_BENCH_OUT", os.path.dirname(os.path.abspath(__file__)))

def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None

def med(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None

def fmt(v, nd=1):
    return "" if v is None else f"{v:.{nd}f}"

rows = list(csv.DictReader(open(f"{LANE}/results/runs.csv")))

# restart may re-run a partially-done file; dedupe by rep keeping last row
seen = {}
for r in rows:
    seen[(r["corpus"], r["file"], r["codec"], r["path"], r["rep"])] = r
rows = list(seen.values())

# per (corpus,file,codec): medians + any bad status
groups = collections.defaultdict(list)
for r in rows:
    groups[(r["corpus"], r["file"], r["codec"], r["path"])].append(r)

perfile = {}
issues = []
for (corpus, fname, codec, path), rs in sorted(groups.items()):
    orig = int(rs[0]["orig_bytes"])
    comp_bytes = med([fnum(r["comp_bytes"]) for r in rs])
    cs = med([fnum(r["comp_s"]) for r in rs])
    ds = med([fnum(r["decomp_s"]) for r in rs])
    rc = med([fnum(r["rss_comp_mb"]) for r in rs])
    rd = med([fnum(r["rss_decomp_mb"]) for r in rs])
    bad = [r for r in rs if r["status"] not in ("ok", "skipped-ratio")]
    sha_bad = [r for r in rs if r["sha_ok"] in ("False", "0")]
    skipped = all(r["status"] == "skipped-ratio" for r in rs)
    statuses = ",".join(sorted({r["status"] for r in rs}))
    if bad or sha_bad:
        issues.append((corpus, fname, codec, statuses,
                       "; ".join(r["note"] for r in rs if r["note"])[:300]))
    perfile[(corpus, fname, codec)] = dict(
        path=path, orig=orig, comp=comp_bytes,
        ratio=(comp_bytes / orig if comp_bytes and orig else None),
        comp_mbps=(orig / cs / 1e6 if cs else None),
        decomp_mbps=(orig / ds / 1e6 if ds else None),
        rss_c=rc, rss_d=rd, status=statuses)

# corpus x codec aggregate: sum(orig)/sum(comp) ratio, sum(orig)/sum(time) mbps
agg = collections.defaultdict(lambda: dict(orig=0, comp=0, ct=0.0, dt=0.0,
                                           rssc=[], rssd=[], n=0, skipped=0))
for (corpus, fname, codec), d in perfile.items():
    a = agg[(corpus, codec)]
    a["n"] += 1
    if d["status"] == "skipped-ratio":
        a["skipped"] += 1
    a["orig"] += d["orig"]
    if d["comp"] is not None:
        a["comp"] += d["comp"]
    if d["comp_mbps"]:
        a["ct"] += d["orig"] / (d["comp_mbps"] * 1e6)
    if d["decomp_mbps"]:
        a["dt"] += d["orig"] / (d["decomp_mbps"] * 1e6)
    if d["rss_c"] is not None:
        a["rssc"].append(d["rss_c"])
    if d["rss_d"] is not None:
        a["rssd"].append(d["rss_d"])

mode = sys.argv[1] if len(sys.argv) > 1 else "agg"

if mode == "agg":
    print(f"{'corpus':<11}{'codec':<9}{'path':<8}{'n':>3} {'ratio':>7} {'saved%':>7} "
          f"{'cMB/s':>8} {'dMB/s':>8} {'rssC':>6} {'rssD':>6} {'skip':>4}")
    for (corpus, codec), a in sorted(agg.items()):
        path = next(v["path"] for k, v in perfile.items()
                    if k[0] == corpus and k[2] == codec)
        ratio = a["comp"] / a["orig"] if a["orig"] else None
        cm = a["orig"] / a["ct"] / 1e6 if a["ct"] else None
        dm = a["orig"] / a["dt"] / 1e6 if a["dt"] else None
        print(f"{corpus:<11}{codec:<9}{path:<8}{a['n']:>3} {fmt(ratio,3):>7} "
              f"{fmt(100*(1-ratio),1) if ratio else '':>7} {fmt(cm):>8} {fmt(dm):>8} "
              f"{fmt(max(a['rssc']) if a['rssc'] else None):>6} "
              f"{fmt(max(a['rssd']) if a['rssd'] else None):>6} {a['skipped']:>4}")
elif mode == "files":
    print(f"{'file':<38}{'codec':<9}{'orig':>11} {'comp':>11} {'ratio':>7} "
          f"{'cMB/s':>8} {'dMB/s':>8} {'status':<14}")
    for (corpus, fname, codec), d in sorted(perfile.items()):
        f = f"{corpus}/{fname}"
        print(f"{f:<38}{codec:<9}{d['orig']:>11} "
              f"{int(d['comp']) if d['comp'] is not None else '':>11} "
              f"{fmt(d['ratio'],3):>7} {fmt(d['comp_mbps']):>8} "
              f"{fmt(d['decomp_mbps']):>8} {d['status']:<14}")
elif mode == "issues":
    for i in issues:
        print(i)
    print(f"{len(issues)} problem rows")
elif mode == "csv":
    w = csv.writer(sys.stdout)
    w.writerow(["corpus","file","codec","path","orig","comp","ratio",
                "comp_mbps","decomp_mbps","rss_c","rss_d","status"])
    for (corpus, fname, codec), d in sorted(perfile.items()):
        w.writerow([corpus, fname, codec, d["path"], d["orig"],
                    int(d["comp"]) if d["comp"] is not None else "",
                    fmt(d["ratio"], 4), fmt(d["comp_mbps"]), fmt(d["decomp_mbps"]),
                    fmt(d["rss_c"]), fmt(d["rss_d"]), d["status"]])
