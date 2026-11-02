import Foundation
import Darwin
import HajimiCore

/// Link against the root's already-built Core/native objects. Memory-only:
/// no SwiftPM invocation, socket, DNS, live profile, interface or Helper I/O.
@main
enum CppPhysicalScopeMain {
    static func main() {
        do {
            try NativeCXXBootstrapOwnershipSelfTest.run()
            try NativeCXXPhysicalScopeIsolationSelfTest.run()
            try NativeCXXDatagramLifecycleSelfTest.run()
            print("PASS C++ physical scope isolation, real handshake cancellation, publication, capacity attribution, and UDP lifecycle")
        } catch {
            fputs("FAIL C++ physical scope regression: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}
