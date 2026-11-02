import Foundation
import HajimiDNS
import Darwin

/// Measures the production wire inspector and answer cache, without a resolver,
/// app profile, listener or network. No alternative parser is timed here.
@main
enum DNSWirePerformanceMain {
    struct Failure: Error { let message: String }
    struct Fixture {
        let name: String
        let query: Data
        let response: Data
    }
    static func append16(_ value: Int, to data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }
    static func fixture(_ name: String, type: UInt16, records: Int = 1) throws -> Fixture {
        guard var query = DNSMessageInspection.query(for: "wire.performance.example.test", type: type, id: 0x1234),
              let question = DNSMessageInspection.singleQuestion(in: query) else {
            throw Failure(message: "Cannot prepare bounded DNS question")
        }
        if records > 1 {
            query[11] = 1
            query.append(contentsOf: [0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0])
        }
        var response = Data(query.prefix(question.questionEnd))
        response[2] = 0x81; response[3] = 0x80
        response[6] = UInt8(records >> 8); response[7] = UInt8(records & 255)
        response[10] = 0; response[11] = 0
        for index in 0..<records {
            response.append(contentsOf: [0xc0, 0x0c])
            append16(Int(type), to: &response); append16(1, to: &response)
            response.append(contentsOf: [0, 0, 0, 60])
            let payload: Data
            switch type {
            case 1: payload = Data([198, 51, 100, UInt8(1 + index % 200)])
            case 28: payload = Data([0x20, 1, 0x0d, 0xb8] + Array(repeating: 0, count: 11) + [7])
            case 65:
                // ServiceMode, root TargetName, ALPN h2/h3 and an IPv4 hint.
                payload = Data([0, 1, 0, 0, 1, 0, 6, 2, 104, 50, 2, 104, 51,
                                0, 4, 0, 4, 198, 51, 100, 7])
            default: throw Failure(message: "Unsupported fixed benchmark type")
            }
            append16(payload.count, to: &response); response.append(payload)
        }
        return Fixture(name: name, query: query, response: response)
    }

    static func main() throws {
        let arguments = CommandLine.arguments
        let profiling = arguments.count == 2 && arguments[1] == "--profile"
        var iterations = 20_000
        if arguments.count == 3 && arguments[1] == "--iterations", let count = Int(arguments[2]),
           (1_000...1_000_000).contains(count) {
            iterations = count
        } else if arguments.count != 1 && !profiling {
            throw Failure(message: "Use --iterations 1000...1000000 or --profile")
        }
        let fixtures = try [fixture("A", type: 1), fixture("AAAA", type: 28),
                            fixture("HTTPS", type: 65), fixture("A-64-TTL", type: 1, records: 64)]
        let cache = DNSQueryCache(clock: { Date(timeIntervalSince1970: 100) })
        let prepared = fixtures.map { DNSQueryCache.prepare($0.query) }
        for (index, item) in fixtures.enumerated() {
            guard cache.store(scopeKey: item.name, prepared: prepared[index], response: item.response),
                  cache.lookup(scopeKey: item.name, prepared: prepared[index]) == item.response,
                  DNSMessageInspection.responseMatchesQuery(item.response, query: item.query) else {
                throw Failure(message: "Benchmark fixture did not pass production validation: \(item.name)")
            }
        }
        var checksum: UInt64 = 0
        if profiling {
            FileHandle.standardError.write(Data("DNS wire production profile PID=\(getpid())\n".utf8))
            let deadline = ProcessInfo.processInfo.systemUptime + 12
            while ProcessInfo.processInfo.systemUptime < deadline {
                for (index, item) in fixtures.enumerated() {
                    for _ in 0..<1000 {
                        guard let answer = cache.lookup(scopeKey: item.name, prepared: prepared[index]) else {
                            throw Failure(message: "Prepared cache unexpectedly missed")
                        }
                        checksum &+= UInt64(answer.count + Int(answer[1]))
                    }
                }
            }
            print("DNS wire profile checksum=\(checksum)")
            return
        }
        func measure(_ work: () throws -> Void) rethrows -> Double {
            var samples: [Double] = []
            for _ in 0..<7 {
                let start = DispatchTime.now().uptimeNanoseconds
                for _ in 0..<iterations { try work() }
                let elapsed = DispatchTime.now().uptimeNanoseconds - start
                samples.append(Double(elapsed) / Double(iterations) / 1000)
            }
            return samples.sorted()[samples.count / 2]
        }
        print("Production DNS wire benchmark: median of 7 runs, \(iterations) operations/run, microseconds/operation")
        for (index, item) in fixtures.enumerated() {
            let inspection = measure {
                checksum &+= DNSMessageInspection.responseMatchesQuery(item.response, query: item.query) ? 1 : 0
            }
            let hit = try measure {
                guard let answer = cache.lookup(scopeKey: item.name, prepared: prepared[index]) else {
                    throw Failure(message: "Prepared cache unexpectedly missed")
                }
                checksum &+= UInt64(answer.count)
            }
            let publicHit = try measure {
                guard let answer = cache.lookup(scopeKey: item.name, query: item.query) else {
                    throw Failure(message: "Public cache unexpectedly missed")
                }
                checksum &+= UInt64(answer.count)
            }
            print(String(format: "%@ bytes=%d validate=%.3fus prepared-hit=%.3fus public-hit=%.3fus",
                         item.name, item.response.count, inspection, hit, publicHit))
        }
        print("DNS wire benchmark checksum=\(checksum); excludes policy/queues, upstream IO and TLS")
    }
}
