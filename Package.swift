// swift-tools-version: 5.9
import PackageDescription
import Foundation

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let nativeQUICPrefix = packageRoot + "/.build/Vendor/HajimiQUIC"
let nativeSSHPrefix = packageRoot + "/.build/Vendor/HajimiSSH"
let vendorOpenSSL = packageRoot + "/.build/Vendor/OpenSSL"
let vendorIncludeDir = packageRoot + "/Sources/HajimiProtocolsCXX/VendorInclude"

let nativeOpenSSL: String = {
    let candidates = [
        ProcessInfo.processInfo.environment["HAJIMI_OPENSSL_ROOT"],
        vendorOpenSSL,
        "/usr/local/opt/openssl@3",
        "/opt/homebrew/opt/openssl@3"
    ].compactMap { $0 }
    for candidate in candidates {
        if FileManager.default.fileExists(atPath: candidate + "/include/openssl/core_names.h") &&
           FileManager.default.fileExists(atPath: candidate + "/lib/libcrypto.a") {
            return candidate
        }
    }
    if FileManager.default.fileExists(atPath: "/opt/homebrew/opt/openssl@3/include/openssl/ssl.h") {
        return "/opt/homebrew/opt/openssl@3"
    }
    return "/usr/local/opt/openssl@3"
}()

let nativeProtocolIncludes: [String] = [
    "-I" + vendorIncludeDir,
    "-I" + vendorOpenSSL + "/include",
    "-I" + nativeOpenSSL + "/include",
    "-I/usr/local/opt/openssl@3/include",
    "-I/opt/homebrew/opt/openssl@3/include",
    "-I" + nativeQUICPrefix + "/include",
    "-I" + nativeSSHPrefix + "/include"
]
let nativeProtocolLibraries: [String] = [
    nativeQUICPrefix + "/lib/libngtcp2.a",
    nativeQUICPrefix + "/lib/libngtcp2_crypto_ossl.a",
    nativeQUICPrefix + "/lib/libnghttp3.a",
    nativeSSHPrefix + "/lib/libssh2.a",
    nativeOpenSSL + "/lib/libssl.a",
    nativeOpenSSL + "/lib/libcrypto.a"
]
let cppProtocolTarget: Target = .target(
    name: "HajimiProtocolsCXX",
    dependencies: [.target(name: "HajimiProtocolCXX")],
    publicHeadersPath: "include",
    cxxSettings: [
        .headerSearchPath("VendorInclude"),
        .unsafeFlags(nativeProtocolIncludes)
    ],
    linkerSettings: [
        .unsafeFlags(nativeProtocolLibraries),
        .linkedFramework("Security"),
        .linkedFramework("CoreFoundation")
    ]
)
let cppBridgeTarget: Target = .target(
    name: "HajimiCXXProtocolBridge",
    dependencies: [.target(name: "HajimiProtocolsCXX"), .target(name: "HajimiProxyRuntime")],
    publicHeadersPath: "include",
    cxxSettings: [
        .headerSearchPath("../HajimiProtocolsCXX"),
        .headerSearchPath("../HajimiProtocolsCXX/VendorInclude"),
        .unsafeFlags(["-fobjc-arc"] + nativeProtocolIncludes)
    ],
    linkerSettings: [.linkedFramework("Foundation"), .linkedFramework("Network")]
)

let package = Package(
    name: "Hajimi",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "HajimiCore", targets: ["HajimiCore"]),
        .library(name: "HajimiDNS", targets: ["HajimiDNS"]),
        .library(name: "HajimiRouting", targets: ["HajimiRouting"]),
        .library(name: "HajimiRuntime", targets: ["HajimiRuntime"]),
        .library(name: "HajimiUIComponents", targets: ["HajimiUIComponents"]),
        .library(name: "HajimiDiagnosticsUI", targets: ["HajimiDiagnosticsUI"]),
        .library(name: "HajimiDiagnosticsUITestSupport", targets: ["HajimiDiagnosticsUITestSupport"]),
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
            "HajimiDNS",
            "HajimiRouting",
            "HajimiCXXProtocolBridge",
            "HajimiProtocolsCXX",
            "HajimiRoutingCXX",
            "HajimiProtocolCXX",
            "HajimiProxyRuntime"
        ]),
        .target(name: "HajimiIPC"),
        // DNS query coordination owns wire/cache/health/deadlines. Platform
        // transports, route authority and their resource owners stay in Core.
        .target(name: "HajimiDNS"),
        // Value-only routing and policy calculations. Compiled rule programs,
        // cache invalidation, authorization and actual I/O remain in Core.
        .target(name: "HajimiRouting"),
        // Runtime ownership is independent of sockets, AppKit and the root Helper.
        .target(name: "HajimiRuntime"),
        .target(name: "HajimiRuntimeTestSupport", dependencies: ["HajimiRuntime"]),
        // Reused AppKit layout, independent of routing and network owners.
        .target(name: "HajimiUIComponents"),
        // Feature UI consumes existing value snapshots through injected
        // capabilities; App adapters retain platform capture and runtime I/O.
        .target(name: "HajimiDiagnosticsUI", dependencies: [
            "HajimiCore", "HajimiRuntime", "HajimiUIComponents"
        ]),
        // Explicit CLI and standalone regression support. Feature modules
        // never depend on these memory fixtures or assertion implementations.
        .target(name: "HajimiDiagnosticsUITestSupport", dependencies: [
            "HajimiDiagnosticsUI", "HajimiCore", "HajimiRuntime", "HajimiUIComponents"
        ]),
        .target(name: "HajimiNativeCore", dependencies: ["HajimiCore", "HajimiDataPlaneC", "HajimiFlowCXX"]),
        // Data plane runs in the App. The helper only needs IPC + root net config.
        .executableTarget(name: "HajimiApp", dependencies: [
            "HajimiCore", "HajimiIPC", "HajimiNativeCore", "HajimiMacOSObjC",
            "HajimiRuntime", "HajimiRuntimeTestSupport", "HajimiUIComponents", "HajimiDiagnosticsUI",
            "HajimiDiagnosticsUITestSupport"
        ]),
        .executableTarget(name: "HajimiHelper", dependencies: ["HajimiIPC"])
    ],
    cxxLanguageStandard: .cxx17
)
