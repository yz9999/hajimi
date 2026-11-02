import Foundation
import Darwin

/// Compiled with the four NativeCore sources; all other production objects
/// are reused from a completed release build. No App/Helper entry is linked.
@main struct NativeTunnelPacketLoadMain {
    static func main() {
        do {
            if CommandLine.arguments.contains("--native-dataplane-self-test") {
                if let failure = NativeCoreSelfTest.run() { throw CheckFailure(text: failure) }
                print("HajimiNativeCore self-test passed")
            } else if CommandLine.arguments.contains("--native-tunnel-stream-self-test") {
                print(try NativeTunnelStreamRegressionFixture.run())
            } else {
                print(try NativeTunnelStreamRegressionFixture.runPacketLoad())
            }
        } catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }
    private struct CheckFailure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
}
