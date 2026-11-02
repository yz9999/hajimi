import Foundation
import HajimiRuntimeTestSupport

@main
enum RuntimeCoordinatorCheck {
    static func main() throws {
        try RuntimeCoordinatorSelfTest.run()
    }
}
