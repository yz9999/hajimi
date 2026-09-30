// swift-tools-version: 5.9
import PackageDescription
import Foundation

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let nativeQUICPrefix = packageRoot + "/.build/Vendor/HajimiQUIC"
let nativeSSHPrefix = packageRoot + "/.build/Vendor/HajimiSSH"
let defaultOpenSSL = FileManager.default.fileExists(atPath: "/opt/homebrew/opt/openssl@3/include/openssl/ssl.h")
    ? "/opt/homebrew/opt/openssl@3" : "/usr/local/opt/openssl@3"
let nativeOpenSSL = ProcessInfo.processInfo.environment["HAJIMI_OPENSSL_ROOT"] ?? defaultOpenSSL
let nativeProtocolIncludes: [String] = ["-I", nativeOpenSSL + "/include", "-I", nativeQUICPrefix + "/include", "-I", nativeSSHPrefix + "/include"]
let nativeProtocolLibraries: [String] = [
    nativeQUICPrefix + "/lib/libngtcp2.a",
    nativeQUICPrefix + "/lib/libngtcp2_crypto_ossl.a",
    nativeQUICPrefix + "/lib/libnghttp3.a",
    nativeSSHPrefix + "/lib/libssh2.a",
    nativeOpenSSL + "/lib/libssl.a",
    nativeOpenSSL + "/lib/libcrypto.a"
]
let cppProtocolTarget: Target = .target(name: "HajimiProtocolsCXX", dependencies: [.target(name: "HajimiProtocolCXX")],
    publicHeadersPath: "include", cxxSettings: [.unsafeFlags(nativeProtocolIncludes)],
    linkerSettings: [.unsafeFlags(nativeProtocolLibraries), .linkedFramework("Security"), .linkedFramework("CoreFoundation")])
let cppBridgeTarget: Target = .target(name: "HajimiCXXProtocolBridge",
    dependencies: [.target(name: "HajimiProtocolsCXX"), .target(name: "HajimiProxyRuntime")],
    publicHeadersPath: "include", cxxSettings: [.headerSearchPath("../HajimiProtocolsCXX"), .unsafeFlags(["-fobjc-arc"])],
    linkerSettings: [.linkedFramework("Foundation"), .linkedFramework("Network")])

let package = Package(
    name: "Hajimi",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "HajimiCore", targets: ["HajimiCore"]),
        .library(name: "HajimiIPC", targets: ["HajimiIPC"]),
        .library(name: "HajimiNativeCore", targets: ["HajimiNativeCore"]),
        .executable(name: "Hajimi", targets: ["HajimiApp"]),
        .executable(name: "HajimiHelper", targets: ["HajimiHelper"])
    ],
    dependencies: [],
    targets: [
        cppProtocolTarget,
        cppBridgeTarget,
        // Stateless per-packet codec. Kept in C because the checksum and
        // header work runs tens of thousands of times a second, where Swift's
        // `Data` copies and ARC traffic dominated the cost.
        .target(name: "HajimiDataPlaneC", path: "Sources/HajimiDataPlaneC",
                publicHeadersPath: "include"),
        // Allocation-free ASCII rule matching on the domain-routing hot path.
        .target(name: "HajimiRoutingCXX", path: "Sources/HajimiRoutingCXX",
                publicHeadersPath: "include"),
        .target(name: "HajimiFlowCXX", publicHeadersPath: "include"),
        .target(name: "HajimiProtocolCXX", publicHeadersPath: "include",
                cxxSettings: [.unsafeFlags(["-fno-exceptions", "-fno-rtti"])]),
        .target(name: "HajimiProxyRuntime", publicHeadersPath: "include",
                cSettings: [.unsafeFlags(["-fobjc-arc"])],
                cxxSettings: [.unsafeFlags(["-fobjc-arc"])],
                linkerSettings: [.linkedFramework("Foundation"),
                                 .linkedFramework("Network"),
                                 .linkedFramework("Security")]),
        .target(name: "HajimiMacOSObjC", publicHeadersPath: "include",
                cSettings: [.unsafeFlags(["-fobjc-arc"])],
                linkerSettings: [.linkedFramework("AppKit"),
                                 .linkedFramework("NetworkExtension"),
                                 .linkedFramework("Security")]),
        .target(name: "HajimiCore", dependencies: [
            "HajimiCXXProtocolBridge",
            "HajimiProtocolsCXX",
            "HajimiRoutingCXX",
            "HajimiProtocolCXX",
            "HajimiProxyRuntime"
        ]),
        .target(name: "HajimiIPC"),
        .target(name: "HajimiNativeCore", dependencies: ["HajimiCore", "HajimiDataPlaneC", "HajimiFlowCXX"]),
        // Data plane runs in the App. The helper only needs IPC + root net config.
        .executableTarget(name: "HajimiApp", dependencies: [
            "HajimiCore", "HajimiIPC", "HajimiNativeCore", "HajimiMacOSObjC"
        ]),
        .executableTarget(name: "HajimiHelper", dependencies: ["HajimiIPC"])
    ],
    cxxLanguageStandard: .cxx17
)
