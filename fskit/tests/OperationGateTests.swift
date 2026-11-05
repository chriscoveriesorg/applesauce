import CryptoKit
import Foundation

@main
struct OperationGateTests {
    static func main() {
        // Two windows use one app-owned gate. A pending mount reserves it
        // throughout extension discovery, access checks and the FSClient call.
        var shared = ASCFOperationGate()
        let firstWindow = shared.begin(.mount, mountedVolumeCount: 0)!
        precondition(shared.isBusy && shared.isCurrent(firstWindow))
        precondition(shared.begin(.mount, mountedVolumeCount: 0) == nil)
        precondition(shared.begin(.unmount, mountedVolumeCount: 1) == nil)
        precondition(!shared.finish(ASCFOperationGate.Ticket(kind: .mount)))
        precondition(shared.isCurrent(firstWindow))
        print("PASS: windows cannot overlap mount or unmount requests")

        // Discovery, permissions and mount failures all release the same ticket.
        precondition(shared.finish(firstWindow))
        precondition(!shared.isBusy)
        let retry = shared.begin(.mount, mountedVolumeCount: 0)!
        precondition(retry != firstWindow)
        precondition(!shared.finish(firstWindow))
        precondition(shared.isCurrent(retry))
        precondition(shared.finish(retry))
        precondition(!shared.finish(retry))
        print("PASS: failure permits retry; stale callbacks cannot unlock it")

        // Recheck real VFS state when a file picker completes, not just when
        // its window opened the picker. A different window/process may mount.
        for count in [-1, 1, 2, Int.max] {
            precondition(shared.begin(.mount, mountedVolumeCount: count) == nil)
            precondition(!shared.isBusy)
        }
        for count in [-1, 0, 2, Int.max] {
            precondition(shared.begin(.unmount, mountedVolumeCount: count) == nil)
            precondition(!shared.isBusy)
        }
        print("PASS: stale picker and ambiguous VFS mount counts are rejected")

        let unmount = shared.begin(.unmount, mountedVolumeCount: 1)!
        precondition(unmount.kind == .unmount)
        precondition(!shared.finish(retry))
        precondition(shared.isCurrent(unmount))
        precondition(shared.finish(unmount))
        let remount = shared.begin(.mount, mountedVolumeCount: 0)!
        precondition(!shared.finish(unmount))
        precondition(shared.isCurrent(remount))
        precondition(shared.finish(remount))
        print("PASS: unmount and remount have separate callback ownership")

        for _ in 0..<1000 {
            let mount = shared.begin(.mount, mountedVolumeCount: 0)!
            precondition(shared.begin(.mount, mountedVolumeCount: 0) == nil)
            precondition(shared.finish(mount))
            let eject = shared.begin(.unmount, mountedVolumeCount: 1)!
            precondition(!shared.finish(mount))
            precondition(shared.finish(eject))
        }
        precondition(!shared.isBusy)
        print("PASS: 1000 lifecycle cycles preserve exclusive request ownership")

        // An FSClient error can follow a partly completed mount. Recover the
        // verified ASCF VFS path instead of enabling another mount request.
        let orphan = ASCFMountPostflight(
            returnedMount: false, callbackError: true,
            verifiedReturnedPath: nil,
            observedVerifiedPaths: ["/Volumes/Applesauce ASCF"]
        )
        precondition(orphan.hasOrphanedMount)
        precondition(orphan.singleVerifiedPath == "/Volumes/Applesauce ASCF")
        precondition(!orphan.cleanSuccess)

        let clean = ASCFMountPostflight(
            returnedMount: true, callbackError: false,
            verifiedReturnedPath: "/Volumes/Applesauce ASCF",
            observedVerifiedPaths: ["/Volumes/Applesauce ASCF"]
        )
        precondition(clean.cleanSuccess)
        precondition(!clean.hasOrphanedMount)

        // A callback can name a real ASCF mount which disappears between its
        // fstatfs check and the kernel mount-table snapshot. It is no longer
        // mounted, even if its earlier descriptor passed verification.
        let disappeared = ASCFMountPostflight(
            returnedMount: true, callbackError: false,
            verifiedReturnedPath: "/Volumes/Applesauce ASCF",
            observedVerifiedPaths: []
        )
        precondition(!disappeared.cleanSuccess)
        precondition(disappeared.singleVerifiedPath == nil)
        precondition(!disappeared.hasOrphanedMount)
        precondition(disappeared.verifiedPaths.isEmpty)

        // A returned path must not hide a different live ASCF mount.
        let mismatched = ASCFMountPostflight(
            returnedMount: true, callbackError: false,
            verifiedReturnedPath: "/Volumes/Applesauce ASCF",
            observedVerifiedPaths: ["/Volumes/Other ASCF"]
        )
        precondition(!mismatched.cleanSuccess)
        precondition(mismatched.hasOrphanedMount)
        precondition(mismatched.singleVerifiedPath == "/Volumes/Other ASCF")

        let duplicate = ASCFMountPostflight(
            returnedMount: true, callbackError: false,
            verifiedReturnedPath: "/Volumes/Applesauce ASCF",
            observedVerifiedPaths: ["/Volumes/Applesauce ASCF", "/Volumes/Other ASCF"]
        )
        precondition(!duplicate.cleanSuccess)
        precondition(duplicate.hasOrphanedMount)
        precondition(duplicate.singleVerifiedPath == nil)

        // The kernel can report stacked mounts at the same pathname.
        // Even if their paths compare equal, there are still two volumes.
        let stacked = ASCFMountPostflight(
            returnedMount: true, callbackError: false,
            verifiedReturnedPath: "/Volumes/Applesauce ASCF",
            observedVerifiedPaths: [
                "/Volumes/Applesauce ASCF", "/Volumes/Applesauce ASCF"
            ]
        )
        precondition(!stacked.cleanSuccess)
        precondition(stacked.singleVerifiedPath == nil)
        precondition(stacked.verifiedPaths.count == 2)
        precondition(stacked.hasOrphanedMount)

        let unrelated = ASCFMountPostflight(
            returnedMount: true, callbackError: false,
            verifiedReturnedPath: nil, observedVerifiedPaths: []
        )
        precondition(!unrelated.cleanSuccess && !unrelated.hasOrphanedMount)
        print("PASS: mount callback reconciliation detects partial and ambiguous mounts")

        // Host discovery must include the private Terminal acceptance mount.
        // Arbitrary directories and lookalike names do not become trusted
        // merely because the filesystem reports an ASCF type.
        for path in [
            "/Volumes/Applesauce ASCF",
            "/Volumes/Applesauce ASCF 2",
            "/private/tmp/ascf-cli-mount.A2b3C4d5/mount",
        ] {
            precondition(ASCFMountLocation.isAllowed(path), "valid mount rejected: \(path)")
        }
        for path in [
            "", "/", "/Volumes", "/Volumes/", "/Volumes/../tmp/other",
            "/private/tmp/ascf-cli-mount.ABCDEFGH/other",
            "/private/tmp/ascf-cli-mount.short/mount",
            "/private/tmp/ascf-cli-mount.ABCDEFGH/mount/extra",
            "/private/tmp/ascf-cli-mount.ABCDEFGH/../mount",
            "/tmp/ascf-cli-mount.ABCDEFGH/mount",
            "/private/tmp/unrelated/mount", "/Users/example/ascf",
        ] {
            precondition(!ASCFMountLocation.isAllowed(path), "unsafe mount allowed: \(path)")
        }
        print("PASS: kernel mount discovery accepts only host and private acceptance paths")

        // Bind the selected negative-control file to exact source bytes.
        // Both the initial and post-FSClient digest must match the package.
        let testDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ascf-corrupt-proof-" + UUID().uuidString)
        try! FileManager.default.createDirectory(
            at: testDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        let fixture = testDirectory.appendingPathComponent("source.lzraven.corrupt.ascf")
        try! Data("abc".utf8).write(to: fixture)
        let known = try! ASCFCorruptFixtureProof.sha256(fixture)
        precondition(known == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        let large = Data(repeating: 0x5c, count: 2_300_000)
        try! large.write(to: fixture)
        let expectedLarge = SHA256.hash(data: large)
            .map { String(format: "%02x", $0) }.joined()
        precondition(try! ASCFCorruptFixtureProof.sha256(fixture) == expectedLarge)
        precondition(expectedLarge != known)
        // A same-byte atomic pathname replacement must not pass the host's
        // pre-/post-FSClient comparison merely because SHA-256 is unchanged.
        let originalFingerprint = try! ASCFCorruptFixtureProof.fingerprint(fixture)
        let twin = testDirectory.appendingPathComponent("identical-copy.ascf")
        try! large.write(to: twin)
        try! FileManager.default.removeItem(at: fixture)
        try! FileManager.default.moveItem(at: twin, to: fixture)
        let replacementFingerprint = try! ASCFCorruptFixtureProof.fingerprint(fixture)
        precondition(originalFingerprint.sha256 == replacementFingerprint.sha256)
        precondition(originalFingerprint.sourceIdentity != replacementFingerprint.sourceIdentity)
        precondition(originalFingerprint != replacementFingerprint)
        let alias = testDirectory.appendingPathComponent("source.lzmesh.corrupt.ascf")
        try! FileManager.default.createSymbolicLink(at: alias, withDestinationURL: fixture)
        do {
            _ = try ASCFCorruptFixtureProof.sha256(alias)
            preconditionFailure("symlink must be rejected")
        } catch {}
        do {
            _ = try ASCFCorruptFixtureProof.sha256(testDirectory)
            preconditionFailure("directory must be rejected")
        } catch {}
        print("PASS: signed corrupt-fixture SHA-256 is streamed, stable and no-follow")

    }
}
