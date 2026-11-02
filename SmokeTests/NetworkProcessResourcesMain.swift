import Foundation

@main
enum NetworkProcessResourcesMemoryCheck {
    static func main() throws {
        try NetworkProcessResourcesSelfTest.run()
        print("Network process resource memory checks passed: GUI soft limit, hard-limit clamp, no lowering, failure and idempotence")
    }
}
