// Guards the FSKit extension's load/unload lifecycle across concurrent
// callbacks. The caller holds a single lock when consulting this value.
// A cancelled load may finish decoding later, but must never publish a
// volume after unload has invalidated its generation.
import Foundation

struct ASCFResourceLoadGate {
    private var pending: UUID?
    private(set) var loaded = false

    mutating func begin() -> UUID? {
        guard !loaded && pending == nil else { return nil }
        let ticket = UUID()
        pending = ticket
        return ticket
    }

    // Only the operation that reserved this generation can publish.
    mutating func publish(_ ticket: UUID) -> Bool {
        guard !loaded, pending == ticket else { return false }
        pending = nil
        loaded = true
        return true
    }

    mutating func cancel(_ ticket: UUID) {
        if pending == ticket { pending = nil }
    }

    mutating func unload() {
        // Invalidate an in-flight verification before it can publish.
        pending = nil
        loaded = false
    }
}
