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

For each generated resource, the probe invokes explicit `compress -c zlib
--verify`, checks kernel-visible bytes, and requires the `info --json`
attribution to report Zlib and the expected inline-xattr or resource-fork
storage. It then revalidates the strict code signature and executable output,
performs verified restoration, and rechecks both after restoration. All
temporary files are removed on exit. Only the stable, registered Zlib codec is
used.

The stable macOS CI job runs this probe separately from all Raven/Mesh decoder
research. A failing signature, readback, storage attribution, or executable
gate is a real acceptance failure. A passing probe applies only to this
generated ad-hoc signed bundle on the runner. It does not establish that
LaunchServices, Gatekeeper, notarized applications, nested signatures,
quarantine, mmap consumers, running processes or real applications are safe
to mutate. Future bundle-write support requires explicit owner approval,
independent review and a broader disposable-app acceptance matrix. Native
Raven/Mesh decmpfs writes and FSKit #86 remain disabled/frozen.
