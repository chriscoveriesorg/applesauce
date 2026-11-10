# Independent ASCF LZMESH buffer decoding proof (#95)

This is a **conformance tool**, not a native APFS `decmpfs` test. The native
Raven/Mesh write gate (#88) and FSKit physical acceptance (#86) remain closed.

## Reproducible procedure

1. Review [mrowlinson/lzmesh](https://github.com/mrowlinson/lzmesh) and its
   [0BSD license](https://github.com/mrowlinson/lzmesh/blob/8f9d5fd0ffef555b07eaf076bc610404b742f0a8/LICENSE).
   Pin independent decoder sources to commit
   `8f9d5fd0ffef555b07eaf076bc610404b742f0a8` (9 Oct 2026), check
   upstream provenance, then build the C11 port **without linking libcompression**:

   ```sh
   git clone https://github.com/mrowlinson/lzmesh.git
   cd lzmesh
   git checkout --detach 8f9d5fd0ffef555b07eaf076bc610404b742f0a8
   make
   make unit
   ```

2. On a provisioned macOS 27+ host with Apple's supported LZMESH buffer API,
   generate a disposable, unchanged plaintext input and an ASCF archive:

   ```sh
   applesauce archive create generated.bin generated.ascf --codec lzmesh --allow-expansion
   applesauce archive verify generated.ascf
   python3 hack/verify_independent_lzmesh.py \
     --archive generated.ascf \
     --original generated.bin \
     --decoder /path/to/lzmesh/port_cli > independent-mesh-evidence.json
   ```

   Run this on at least two different generated content families and boundary
   sizes, including multi-chunk payloads. The CLI command and exact source
   file must be archived with the evidence JSON and macOS test logs.

3. Inspect the resulting SHA-256 of the archive, original and decoder executable,
   recorded chunk count and bytes. Every ASCF index record is checked before the
   external decoder runs. Each independently decoded chunk must have its exact
   declared length, the original bytes and the ASCF SHA-256, then the complete
   decoded data must match the ASCF whole-file SHA-256. Malformed index geometry
   and insufficient decoder output fail closed. The tool bounds logical fixture
   size to 64 MiB by default; larger tests require an explicit override.

4. Have an independent reviewer inspect the pinned decoder, commands, evidence,
   differences from Apple's `compression_decode_buffer`, and failure cases.
   The synthetic identity-decoder tests run on Linux only to validate the
   proof tool's format and error handling; they **cannot** establish LZMESH
   interoperability.

## Limitations

The tool executes an **explicitly supplied** binary. It does not download code
or promote a decoder to a project dependency. Audit and build that executable
in an isolated environment. The upstream decoder documentation notes that
a destination with insufficient capacity may silently truncate; this proof
requires byte-for-byte equality and exact output length before accepting any
decode. A successful Apple-buffer-to-C decoder comparison does not show that
macOS registers an LZMESH `decmpfs` handler or that FSKit is mountable.
