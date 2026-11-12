# Disposable signed-app verification for issue #93

This is a **test of the current stable Zlib APFS writer** and of the read-only
`compress --dry-run --profile bundles` classifier. It does not enable
`--profile bundles` for mutating compression and does not touch installed
applications.

Run on a macOS APFS checkout after building the CLI:

```sh
cargo build --locked -p applesauce-cli
python3 hack/bundle-codesign-probe.py target/debug/applesauce
```

The probe constructs a temporary `.app` **under the current checkout volume**,
compiles a minimal C executable, writes an Info.plist, creates two resource
fixtures, and signs the bundle ad hoc with `codesign -s -`. It first requires a
strict/deep signature verification and successfully executes the generated
binary. The bundle-profile dry run must select the two data resources and
preserve resource bytes, mtimes and xattrs, sealed CodeResources and executable
content exactly.

The probe compresses **both generated resources before restoring either**:
one inline-xattr and one resource-fork Zlib file coexist inside the signed
bundle. After every compression and reverse-order restoration, it rereads
all still-compressed files through the kernel and read-only `mmap`, checks
their original full SHA-256, and requires `info --json` to show the expected
Zlib/decmpfs storage attribution. It also checks strict bundle code signing,
direct executable behavior, and unchanged signature-manifest/executable
bytes, mtimes and xattrs at every transition. Every restored resource is
rechecked with both read methods.
All temporary files are removed on exit. Only the stable, registered Zlib
codec is used.

The probe snapshots extended attributes using macOS `/usr/bin/xattr`
(including hex-encoded binary values), because the macOS Python runtime
does not expose `os.listxattr`/`os.getxattr`. Missing or unreadable attributes
fail acceptance. The portable fast gate
`python3 -m unittest discover -s hack -p 'test_bundle_codesign_probe.py'`
covers snapshot errors, binary values, mmap/kernel corruption, signed-seal mutation and invalid storage reports before macOS execution.

The stable macOS CI job runs this probe separately from all Raven/Mesh decoder
research. A failing signature, readback, storage attribution, or executable
gate is a real acceptance failure. A passing probe applies only to this
generated ad-hoc signed bundle on the runner. It does not establish that
LaunchServices, Gatekeeper, notarized applications, nested signatures,
quarantine, mmap consumers, running processes or real applications are safe
to mutate. Future bundle-write support requires explicit owner approval,
independent review and a broader disposable-app acceptance matrix. Native
Raven/Mesh decmpfs writes and FSKit #86 remain disabled/frozen.
