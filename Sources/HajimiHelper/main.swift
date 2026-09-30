import Foundation
import Darwin
import HajimiIPC

signal(SIGPIPE, SIG_IGN)

func printError(_ value: String) {
    FileHandle.standardError.write(Data((value + "\n").utf8))
}

if CommandLine.arguments.contains("--self-test") {
    do {
        try FakeIPDNSRedirectSelfTest.run()
    } catch {
        printError(error.localizedDescription)
        exit(1)
    }
    print("HajimiHelper self-test passed")
    exit(0)
}

if CommandLine.arguments.contains("--version") {
    print("HajimiHelper protocol \(HajimiHelperProtocol.version).\(HajimiHelperProtocol.buildRevision)")
    exit(0)
}

guard geteuid() == 0 else {
    printError("HajimiHelper must run as root")
    exit(77)
}
guard let uidIndex = CommandLine.arguments.firstIndex(of: "--uid"),
      CommandLine.arguments.indices.contains(uidIndex + 1),
      let allowedUID = uid_t(CommandLine.arguments[uidIndex + 1]),
      allowedUID > 0 else {
    printError("HajimiHelper requires --uid <local-user-id>")
    exit(64)
}

do {
    let service = EnhancedTunnelService()
    let server = HelperSocketServer(allowedUID: allowedUID, service: service)
    try server.start()

    signal(SIGTERM, SIG_IGN)
    signal(SIGINT, SIG_IGN)
    let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    termination.setEventHandler {
        _ = try? service.stop()
        server.stop()
        exit(0)
    }
    termination.resume()
    let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    interruption.setEventHandler {
        _ = try? service.stop()
        server.stop()
        exit(0)
    }
    interruption.resume()
    dispatchMain()
} catch {
    printError(error.localizedDescription)
    exit(1)
}
