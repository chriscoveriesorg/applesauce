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

    var verifiedPaths: [String] {
        Array(Set(observedVerifiedPaths + (verifiedReturnedPath.map { [$0] } ?? []))).sorted()
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
