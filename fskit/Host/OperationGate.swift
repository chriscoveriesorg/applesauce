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
