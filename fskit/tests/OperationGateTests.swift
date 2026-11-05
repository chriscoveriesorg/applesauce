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
            observedVerifiedPaths: []
        )
        precondition(clean.cleanSuccess)
        precondition(!clean.hasOrphanedMount)

        let duplicate = ASCFMountPostflight(
            returnedMount: true, callbackError: false,
            verifiedReturnedPath: "/Volumes/Applesauce ASCF",
            observedVerifiedPaths: ["/Volumes/Applesauce ASCF", "/Volumes/Other ASCF"]
        )
        precondition(!duplicate.cleanSuccess)
        precondition(duplicate.hasOrphanedMount)
        precondition(duplicate.singleVerifiedPath == nil)

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
    }
}
