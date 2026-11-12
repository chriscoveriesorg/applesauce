#!/usr/bin/env bash
# Manual, disposable-host qualification of a second LZRAVEN C11 candidate.
# A human source/lineage review is required before evidence is accepted.
set -euo pipefail

if [[ "$#" -gt 1 ]]; then
  echo "usage: bash hack/run_second_raven_proof.sh [PATH_TO_APPLESAUCE_CLI]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/applesauce-raven-second.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
pinned_commit='6d97f1ab520821b4d326139fdf48b658f96ee5b9'
upstream="$work/apple-compressions"

# Pull exactly the reviewed upstream revision. Avoid mutable upstream HEAD.
git clone --quiet --filter=blob:none https://github.com/retrowave3/apple-compressions.git "$upstream"
git -C "$upstream" checkout --quiet --detach "$pinned_commit"
test "$(git -C "$upstream" rev-parse HEAD)" = "$pinned_commit"

cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$upstream/lzbitmap.c" "$upstream/lzmesh.c" "$upstream/lzraven.c" \
  "$upstream/tests/test.c" -o "$work/upstream-tests"
"$work/upstream-tests"
cc -std=c11 -O2 -Wall -Wextra -Werror -I "$upstream" \
  "$upstream/lzraven.c" "$repo_root/hack/retrowave3_lzraven_decode.c" \
  -o "$work/raven-second"

# Check the built executable for dynamic dependence on Apple's codec.
if [[ "$(uname -s)" == Darwin ]]; then
  if otool -L "$work/raven-second" | grep -qi libcompression; then
    echo 'second LZRAVEN candidate links against libcompression' >&2
    exit 1
  fi
else
  if ldd "$work/raven-second" | grep -qi libcompression; then
    echo 'second LZRAVEN candidate links against libcompression' >&2
    exit 1
  fi
fi

python3 -m unittest discover -s "$repo_root/hack" \
  -p 'test_retrowave3_lzraven_cli.py' -v
# This existing harness independently verifies fixture provenance, SHA-256,
# codec ID, two- and three-chunk geometry and decoded bytes.
python3 "$repo_root/hack/prove_committed_vectors.py" \
  --codec lzraven --decoder "$work/raven-second" > "$work/committed.json"
echo 'PASS: second decoder restored two committed Apple LZRAVEN vectors'

if [[ "$#" -eq 1 ]]; then
  cli="$1"
  if [[ ! -x "$cli" || "$(uname -s)" != Darwin ]]; then
    echo 'fresh Apple-buffer proof requires executable Applesauce CLI on macOS' >&2
    exit 2
  fi
  python3 - "$work" <<'PY'
from pathlib import Path
import hashlib
import sys

root = Path(sys.argv[1])
row = b'{"event":"agent","turn":27,"payload":"repeatable proof"}\n'
for length in (65535, 65536, 65537, 131103, 262151):
    for family in ("records", "digest"):
        if family == "records":
            data = (row * (length // len(row) + 1))[:length]
        else:
            data = b"".join(
                hashlib.sha256(f"{length}:{i}".encode()).digest()
                for i in range((length + 31) // 32)
            )[:length]
        (root / f"{family}-{length}.bin").write_bytes(data)
PY
  completed=0
  for input in "$work"/*.bin; do
    archive="${input%.bin}.ascf"
    "$cli" archive create "$input" "$archive" \
      --codec lzraven --allow-expansion --chunk-bytes 65536
    "$cli" archive verify "$archive"
    python3 "$repo_root/hack/verify_independent_lzmesh.py" \
      --archive "$archive" --original "$input" \
      --decoder "$work/raven-second" --codec lzraven > "${input%.bin}.json"
    completed=$((completed + 1))
  done
  test "$completed" -eq 10
  echo 'PASS: second decoder restored ten freshly Apple-encoded ASCF fixtures'

  for family in records digest; do
    # Existing qualification harness rejects nine independent corruptions
    # for each three-chunk Apple-generated archive and proves the baseline.
    python3 "$repo_root/hack/prove_independent_corruptions.py" \
      --archive "$work/$family-131103.ascf" \
      --original "$work/$family-131103.bin" \
      --decoder "$work/raven-second" --codec lzraven \
      > "$work/$family-negative.json"
  done
  echo 'PASS: second decoder rejected 18 independently checked corruptions'
fi

printf 'Upstream source commit: %s\n' "$pinned_commit"
cat "$work/committed.json"
