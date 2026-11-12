#!/usr/bin/env bash
# Disposable-host qualification of a second, source-pinned LZRAVEN decoder.
# A human source/lineage review is required before evidence is accepted.
set -euo pipefail

usage() {
  echo 'usage: bash hack/run_second_raven_proof.sh [--upstream-checkout DIR] [--evidence-dir NEW_DIR] [PATH_TO_APPLESAUCE_CLI]' >&2
  exit 2
}

source_checkout=''
evidence_target=''
cli=''
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --upstream-checkout|--evidence-dir)
      [[ "$#" -ge 2 && -n "$2" ]] || usage
      if [[ "$1" == --upstream-checkout ]]; then
        [[ -z "$source_checkout" ]] || usage
        source_checkout="$2"
      else
        [[ -z "$evidence_target" ]] || usage
        evidence_target="$2"
      fi
      shift 2 ;;
    --help|-h) usage ;;
    --*) usage ;;
    *) [[ -z "$cli" ]] || usage; cli="$1"; shift ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Attested evidence must come from a clean checkout. Refuse a missing or
# pre-existing output destination before running expensive decoder tests.
git -C "$repo_root" diff --quiet HEAD -- || {
  echo 'Applesauce tracked source is dirty' >&2; exit 1;
}
if [[ -n "$evidence_target" ]]; then
  if [[ -e "$evidence_target" || -L "$evidence_target" ]]; then
    echo 'evidence destination already exists' >&2; exit 1
  fi
  [[ -d "$(dirname "$evidence_target")" ]] || {
    echo 'evidence parent directory does not exist' >&2; exit 1;
  }
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/applesauce-raven-second.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
pinned_commit='6d97f1ab520821b4d326139fdf48b658f96ee5b9'
evidence="$work/evidence"
mkdir -m 700 "$evidence"

if [[ -n "$source_checkout" ]]; then
  # Offline GARM runners can use a pre-fetched pinned source checkout.
  # Compilation products are written to the private work directory.
  upstream="$(cd "$source_checkout" && pwd -P)"
else
  upstream="$work/apple-compressions"
  git clone --quiet --filter=blob:none https://github.com/retrowave3/apple-compressions.git "$upstream"
  git -C "$upstream" checkout --quiet --detach "$pinned_commit"
fi
[[ "$(git -C "$upstream" rev-parse HEAD)" == "$pinned_commit" ]] || {
  echo 'upstream checkout is not the pinned source revision' >&2; exit 1;
}
git -C "$upstream" diff --quiet HEAD -- || {
  echo 'upstream tracked source is dirty' >&2; exit 1;
}
audit_files=(lzraven.c lzraven.h lzbitmap.c lzbitmap.h lzmesh.c lzmesh.h tests/test.c tests/vectors.h)
for path in "${audit_files[@]}"; do
  [[ -f "$upstream/$path" && ! -L "$upstream/$path" ]] || {
    echo "missing regular upstream source: $path" >&2; exit 1;
  }
done

cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$upstream/lzbitmap.c" "$upstream/lzmesh.c" "$upstream/lzraven.c" \
  "$upstream/tests/test.c" -o "$work/upstream-tests"
"$work/upstream-tests" > "$evidence/upstream-tests.log" 2>&1
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
  -p 'test_retrowave3_lzraven_cli.py' -v \
  > "$evidence/adapter-tests.log" 2>&1
python3 -m unittest discover -s "$repo_root/hack" \
  -p 'test_second_raven_reports.py' -v \
  > "$evidence/evidence-tests.log" 2>&1
# This existing harness independently verifies fixture provenance, SHA-256,
# codec ID, two- and three-chunk geometry and decoded bytes.
python3 "$repo_root/hack/prove_committed_vectors.py" \
  --codec lzraven --decoder "$work/raven-second" > "$evidence/committed.json"
echo 'PASS: second decoder restored two committed Apple LZRAVEN vectors'

fresh_option=()
if [[ -n "$cli" ]]; then
  mkdir "$evidence/fresh" "$evidence/negative"
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
    label="$(basename "${input%.bin}")"
    archive="${input%.bin}.ascf"
    "$cli" archive create "$input" "$archive" \
      --codec lzraven --allow-expansion --chunk-bytes 65536
    "$cli" archive verify "$archive"
    python3 "$repo_root/hack/verify_independent_lzmesh.py" \
      --archive "$archive" --original "$input" \
      --decoder "$work/raven-second" --codec lzraven > "$evidence/fresh/$label.json"
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
      > "$evidence/negative/$family.json"
  done
  fresh_option=(--fresh)
fi

# Revalidate source cleanliness after compilation and qualification.
git -C "$repo_root" diff --quiet HEAD -- || {
  echo 'Applesauce tracked source changed during qualification' >&2; exit 1;
}
git -C "$upstream" diff --quiet HEAD -- || {
  echo 'upstream tracked source changed during qualification' >&2; exit 1;
}
cli_option=()
[[ -z "$cli" ]] || cli_option=(--cli "$cli")
# Require every expected report, exact positive counts and corruption cases.
# Bind all proof records to the decoder binary and pinned source hashes.
python3 "$repo_root/hack/validate_second_raven_reports.py" \
  --reports "$evidence" --decoder "$work/raven-second" \
  --upstream "$upstream" --repository "$repo_root" \
  "${fresh_option[@]}" "${cli_option[@]}"

if [[ -n "$evidence_target" ]]; then
  # The output parent must be trusted. A new directory avoids overwriting
  # previous evidence. Source reports are retained without codec binaries.
  if [[ -e "$evidence_target" || -L "$evidence_target" ]]; then
    echo 'evidence destination already exists' >&2
    exit 1
  fi
  mkdir -m 700 -- "$evidence_target"
  cp -R "$evidence/." "$evidence_target/"
  printf 'Evidence retained in: %s\n' "$evidence_target"
else
  echo 'Specify --evidence-dir NEW_DIR to retain the qualification evidence.'
fi
printf 'Upstream source commit: %s\n' "$pinned_commit"
cat "$evidence/manifest.json"
