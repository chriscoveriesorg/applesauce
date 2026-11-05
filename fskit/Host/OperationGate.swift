// Shared by every host window through the app-owned mount controller.
// The controller confines all mutations to the main actor. No FSKit calls
// or filesystem side effects occur here, so lifecycle races are testable.
import Foundation

struct ASCFOperationGate {
    enum Kind: Equatable { case mount, unmount }

    struct Ticket: Equatable {
        let id = UUID()
        let kind: Kind
    }

    private(set) var pending: Ticket?
    var isBusy: Bool { pending != nil }

    // Counts come from a fresh VFS inspection. Ambiguous multiple mounts
    // require operator resolution, including when a picker was already open.
    mutating func begin(_ kind: Kind, mountedVolumeCount: Int) -> Ticket? {
        guard pending == nil else { return nil }
        switch kind {
        case .mount:
            guard mountedVolumeCount == 0 else { return nil }
        case .unmount:
            guard mountedVolumeCount == 1 else { return nil }
        }
        let ticket = Ticket(kind: kind)
        pending = ticket
        return ticket
    }

    func isCurrent(_ ticket: Ticket) -> Bool { pending == ticket }

    // A late/duplicate callback must never unlock a newer request, even if
    // that request has the same operation kind or uses the same archive.
    @discardableResult
    mutating func finish(_ ticket: Ticket) -> Bool {
        guard isCurrent(ticket) else { return false }
        pending = nil
        return true
    }
}
 
// A mount callback can disagree with the live VFS (e.g. a partial mount
// followed by an error). Preserve the discovered read-only ASCF volume in
// that case so the host can offer a normal unmount instead of losing track
// of a mounted filesystem. This classifier has no FSKit dependency.
struct ASCFMountPostflight {
    let returnedMount: Bool
    let callbackError: Bool
    let verifiedReturnedPath: String?
    let observedVerifiedPaths: [String]

    // Only the live kernel table is authoritative for mount ownership.
    // A callback pathname may pass fstatfs and disappear before getmntinfo.
    // Never resurrect that stale pathname as an active volume.
    var verifiedPaths: [String] {
        // Preserve duplicates: stacked VFS mounts can share a pathname.
        // Deduplication would classify two live ASCF mounts as one.
        observedVerifiedPaths.sorted()
    }

    var singleVerifiedPath: String? {
        verifiedPaths.count == 1 ? verifiedPaths[0] : nil
    }

    var cleanSuccess: Bool {
        !callbackError && returnedMount && verifiedReturnedPath != nil
            && singleVerifiedPath == verifiedReturnedPath
    }

    var hasOrphanedMount: Bool {
        !verifiedPaths.isEmpty && !cleanSuccess
    }
}

// Only accept mount locations that the signed host or disposable Terminal
 // acceptance path can create. An unrelated ASCF mount elsewhere must block
 // another mount attempt instead of being treated as an ordinary host volume.
enum ASCFMountLocation {
    static func isAllowed(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        if parts.count == 3, parts[0].isEmpty, parts[1] == "Volumes" {
            return !parts[2].isEmpty && parts[2] != "." && parts[2] != ".."
        }
        guard parts.count == 5, parts[0].isEmpty,
              parts[1] == "private", parts[2] == "tmp",
              parts[4] == "mount", parts[3].hasPrefix("ascf-cli-mount.") else {
            return false
        }
        let suffix = parts[3].dropFirst("ascf-cli-mount.".count)
        return suffix.utf8.count == 8 && suffix.utf8.allSatisfy { byte in
            (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
        }
    }
}
