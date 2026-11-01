# Foldy + sessions + Applesauce + ZGX: one verified storage workflow

**State:** a working *contract checker* and a reproducible test plan; not a
four-tool daemon, not automatic deletion, and not native LZRAVEN/LZMESH.

This is the integration hub for the [Applesauce fork](https://github.com/chriscoveriesorg/applesauce),
[compress-agent-sessions](https://github.com/chriscoveriesorg/compress-agent-sessions),
[ZGX](https://github.com/chriscoveriesorg/zgx), and
[Foldy](https://github.com/chriscoveries/foldy). ZGX and Foldy are private:
the public test uses only their documented output schemas, never their code
or anyone's session logs.

## Ownership and data flow

1. **Foldy inventories.** `foldy-disk --sha256` identifies paths and hashes
   using stable `local:<host>:<root+relpath digest>` IDs. It discovers duplicates
   for review; compression is *not* a duplicate-deletion decision. A compression
   pass must not turn the same logical file into a new Foldy identity.
2. **compress-agent-sessions selects.** It handles age, open handles, active
   grace, path exclusions, operator dry runs, ledger and restore. It may invoke
   the installed Applesauce binary, but never infers a native codec merely
   from its OS version or ability to benchmark buffers.
3. **Applesauce transforms storage.** Production `LZFSE`/`LZVN`/`ZLIB` preserve
   ordinary APFS reads; opt-in `LZBitmap` is gated and verified. Native Raven
   and Mesh remain unavailable until their decmpfs IDs/framing/decoder are
   independently proven. `applesauce capabilities --json --require-native CODEC`
   is the machine gate. The experimental `benchmark-codecs` command measures
   *buffer* performance, not disk space saved.
4. **ZGX reads the same logical path.** Native APFS decompression is transparent
   to search clients. Preserve ranked `path`, `span`, `snippet` results and
   original JSONL hashes; ignore incidental receipt scores, timing, cache IDs,
   inode and ctime differences. Do not start a blanket re-embedding run just
   because file storage changed. See [ZGX #504](https://github.com/chriscoveriesorg/zgx/issues/504).

An eventual FSKit Raven archive is a *different storage tier*: ZGX must index
its mounted **logical** files, never compressed backing chunks. The mount's
path mapping and reattachment need separate acceptance tests.

## The executable acceptance contract

[`family_contract.py`](family_contract.py) is deliberately read-only and
stdlib-only. It checks two independent before/after evidence pairs:

- `foldy_local_inventory/1` from `foldy-disk --sha256`: both inventories must
  be complete, in the same host/root, and have exactly identical file paths,
  stable IDs, logical sizes and SHA256 hashes. Inodes and times may change
  because Applesauce can atomically replace the on-disk representation.
- ZGX `query --json` output: exactly one `type: final` record (optionally
  preceded by trace records), at least one hit, identical **ordered** paths,
  source spans and snippets. Supports protocol-4 positional and `--receipt`
  object hits. Ranking scores, search-leg tags, cache receipts and latency are
  excluded from this logical-content invariant.

An optional pair of measured physical byte counts can make a **real
allocation decrease** a hard gate. Foldy's `Size` is logical size, **not** a
physical allocation measurement; don't subtract it to claim savings.

```sh
python3 hack/family_contract.py \
  --foldy-before /path/outside/corpus/foldy-before.json \
  --foldy-after /path/outside/corpus/foldy-after.json \
  --zgx-before /path/outside/corpus/zgx-before.jsonl \
  --zgx-after /path/outside/corpus/zgx-after.jsonl \
  --physical-before-bytes 8192 \
  --physical-after-bytes 4096 \
  --require-physical-saving
```

Exit 0 emits a small `applesauce_family_contract/1` JSON summary. Exit 1
indicates a failed contract. Missing/partial/incomplete Foldy inventories,
unhashed files and empty ZGX search results **fail closed**. Only pass
physical-byte flags when measured on the same volume with the same method;
the numbers above are illustrative, not benchmark results.

## Disposable macOS proof: LZFSE first

Use **only generated data** on a disposable APFS folder. Do not point the
recipe at active chatlogs; do not run `chflags` on compressed files. Install
the four CLIs separately and ensure they are on `PATH` before starting.
Store the before/after JSON evidence *outside* the scanned corpus.

```sh
applesauce capabilities --json --require-native lzfse

LAB=$(mktemp -d "${TMPDIR:-/tmp}/applesauce-family.XXXXXXXX")
mkdir -p "$LAB/corpus" "$LAB/evidence"
for i in $(seq 1 8000); do
  printf '{"role":"assistant","content":"family-contract-canary repeated test line %s"}\n' "$((i % 10))"
done > "$LAB/corpus/session.jsonl"
touch -t 202501010000 "$LAB/corpus/session.jsonl"

HOST_ID=$(hostname -s)
foldy-disk --root "$LAB/corpus" --host "$HOST_ID" --sha256 -o "$LAB/evidence/foldy-before.json"
zgx query "family-contract-canary" --adhoc --root "$LAB/corpus" --json > "$LAB/evidence/zgx-before.jsonl"
BEFORE_KIB=$(du -sk "$LAB/corpus" | awk '{print $1}')

compress-agent-sessions compress --dry-run --age-days 1 --tool applesauce --algorithm LZFSE "$LAB/corpus"
# Inspect the planned paths and skips. Explicit opt-in for this generated corpus:
compress-agent-sessions compress --age-days 1 --tool applesauce --algorithm LZFSE "$LAB/corpus"

foldy-disk --root "$LAB/corpus" --host "$HOST_ID" --sha256 -o "$LAB/evidence/foldy-after.json"
zgx query "family-contract-canary" --adhoc --root "$LAB/corpus" --json > "$LAB/evidence/zgx-after.jsonl"
AFTER_KIB=$(du -sk "$LAB/corpus" | awk '{print $1}')

python3 hack/family_contract.py \
  --foldy-before "$LAB/evidence/foldy-before.json" \
  --foldy-after "$LAB/evidence/foldy-after.json" \
  --zgx-before "$LAB/evidence/zgx-before.jsonl" \
  --zgx-after "$LAB/evidence/zgx-after.jsonl" \
  --physical-before-bytes "$((BEFORE_KIB * 1024))" \
  --physical-after-bytes "$((AFTER_KIB * 1024))" \
  --require-physical-saving
```

Requirements/caveats:

- `zgx --adhoc` creates a temporary index and needs its model/tool setup;
  use a single configured index and the same query before/after if preferred.
  Check its **logical results**, not the variable performance of index builds.
- `compress-agent-sessions` safely skips open/recent/ineligible files; if it
  skips the fixture, **do not fabricate savings or call the test a pass**.
  Inspect its classification and ledger, then adjust *the generated fixture*.
- `du -sk` is a coarse directory allocation sample (KiB rounding). A useful
  performance benchmark separately records encode/decode latency, actual
  allocated bytes, cold session sizes, and repeated trials. See
  [benchmark standards](benchmark-standard.md).
- Never change the test to request `LZRAVEN` or `LZMESH` native writes until
  `applesauce capabilities --json --require-native lzraven` (or `lzmesh`)
  succeeds after independent safe decoder qualification. Today it is
  expected to fail. See [codec roadmap](roadmap-lzraven.md).
- A matching post-compression digest is necessary but not sufficient: also
  test `restore`, append/resume after restoring, and direct normal file reads.
  A bare nonzero `du` delta does not validate search or filesystem safety.

## CI / ownership of the next gates

The public Applesauce CI runs this **portable contract parser** against
synthetic Foldy/ZGX receipts. Full four-binary APFS mutation tests belong on
an explicitly opted-in macOS host with a disposable test corpus. No GitHub
hosted runner gets personal session logs or private Foldy/ZGX code.

| Gate | Owner | Required result |
| --- | --- | --- |
| File eligibility and dry-run plan | Sessions | Exclude active/open files; repeatable paths |
| Native codec support | Applesauce | Machine preflight + verified decmpfs round trip |
| Logical inventory identity | Foldy | Same `ID`, path, logical size and SHA256 |
| Search correctness | ZGX | Same ranked paths, spans, snippets; refresh/reopen succeeds |
| Allocation, throughput, decode latency | Applesauce benchmark + test operator | Measured improvement; no regression on real fixture classes |
| Restore, resumed session append | Sessions | Exact bytes and normal write behavior after restore |

Cross-tool success is **opt-in and evidence-driven**, not an instruction to
automatically compress, move, delete or re-index a user's files.
