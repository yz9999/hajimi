import Foundation
import Darwin

/// Send/receive a single file descriptor over a connected Unix stream using
/// `SCM_RIGHTS`. Used so the root helper can hand the utun descriptor to the
/// unprivileged App without the App needing to create the tunnel itself.
public enum UnixFileDescriptorPassing {
    public enum Error: Swift.Error, LocalizedError {
        case sendFailed(String)
        case receiveFailed(String)
        case noFileDescriptor
        case selfTestFailed(String)

        public var errorDescription: String? {
            switch self {
            case .sendFailed(let value): return "发送文件描述符失败：\(value)"
            case .receiveFailed(let value): return "接收文件描述符失败：\(value)"
            case .noFileDescriptor: return "对端未附带文件描述符"
            case .selfTestFailed(let value): return "文件描述符传递自检失败：\(value)"
            }
        }
    }

    /// Control-message buffer large enough for one `Int32` file descriptor.
    private static var controlBufferLength: Int {
        CMSG_SPACE(MemoryLayout<Int32>.size)
    }

    public static func send(fileDescriptor fd: Int32, on socket: Int32) throws {
        var dummy: UInt8 = 0
        try withUnsafeMutablePointer(to: &dummy) { dummyPointer in
            var io = iovec(iov_base: UnsafeMutableRawPointer(dummyPointer), iov_len: 1)
            try withUnsafeMutablePointer(to: &io) { ioPointer in
                var control = [UInt8](repeating: 0, count: controlBufferLength)
                try control.withUnsafeMutableBytes { controlRaw in
                    var message = msghdr()
                    message.msg_iov = ioPointer
                    message.msg_iovlen = 1
                    message.msg_control = controlRaw.baseAddress
                    message.msg_controllen = socklen_t(controlRaw.count)

                    guard let header = CMSG_FIRSTHDR(&message) else {
                        throw Error.sendFailed("无法构造控制头")
                    }
                    header.pointee.cmsg_len = socklen_t(CMSG_LEN(MemoryLayout<Int32>.size))
                    header.pointee.cmsg_level = SOL_SOCKET
                    header.pointee.cmsg_type = SCM_RIGHTS
                    let dataPointer = UnsafeMutableRawPointer(CMSG_DATA(header))
                        .assumingMemoryBound(to: Int32.self)
                    dataPointer.pointee = fd

                    let sent = withUnsafePointer(to: &message) { sendmsg(socket, $0, 0) }
                    guard sent == 1 else {
                        throw Error.sendFailed(String(cString: strerror(errno)))
                    }
                }
            }
        }
    }

    public static func receive(on socket: Int32) throws -> Int32 {
        var dummy: UInt8 = 0
        return try withUnsafeMutablePointer(to: &dummy) { dummyPointer -> Int32 in
            var io = iovec(iov_base: UnsafeMutableRawPointer(dummyPointer), iov_len: 1)
            return try withUnsafeMutablePointer(to: &io) { ioPointer -> Int32 in
                var control = [UInt8](repeating: 0, count: controlBufferLength)
                return try control.withUnsafeMutableBytes { controlRaw -> Int32 in
                    var message = msghdr()
                    message.msg_iov = ioPointer
                    message.msg_iovlen = 1
                    message.msg_control = controlRaw.baseAddress
                    message.msg_controllen = socklen_t(controlRaw.count)

                    let received = withUnsafeMutablePointer(to: &message) { recvmsg(socket, $0, 0) }
                    guard received >= 0 else {
                        throw Error.receiveFailed(String(cString: strerror(errno)))
                    }
                    guard received > 0 else { throw Error.noFileDescriptor }
                    guard let header = CMSG_FIRSTHDR(&message),
                          header.pointee.cmsg_level == SOL_SOCKET,
                          header.pointee.cmsg_type == SCM_RIGHTS,
                          header.pointee.cmsg_len >= CMSG_LEN(MemoryLayout<Int32>.size) else {
                        throw Error.noFileDescriptor
                    }
                    let dataPointer = UnsafeRawPointer(CMSG_DATA(header))
                        .assumingMemoryBound(to: Int32.self)
                    let fd = dataPointer.pointee
                    // Reject a truncated or multiple-FD response; in particular,
                    // do not leak the first descriptor if a peer sent two.
                    guard message.msg_flags & MSG_CTRUNC == 0,
                          header.pointee.cmsg_len == CMSG_LEN(MemoryLayout<Int32>.size) else {
                        Darwin.close(fd)
                        throw Error.receiveFailed("SCM_RIGHTS 必须只含一个完整的描述符")
                    }
                    return fd
                }
            }
        }
    }

    /// No utun, root permission, DNS, or routes: exercise both directions over
    /// a private socketpair, including an independent count of transferred FDs.
    /// The count catches an ABI regression where sender and receiver both use
    /// the same incorrect offset and accidentally appear to work together.
    public static func runSelfTest() throws {
        guard MemoryLayout<cmsghdr>.size == 12,
              CMSG_LEN(MemoryLayout<Int32>.size) == 16,
              controlBufferLength == 16 else {
            throw Error.selfTestFailed("Darwin SCM_RIGHTS 布局与预期不符")
        }
        var sockets: [Int32] = [-1, -1]
        let paired = sockets.withUnsafeMutableBufferPointer { buffer in
            socketpair(AF_UNIX, SOCK_STREAM, 0, buffer.baseAddress!)
        }
        guard paired == 0 else {
            throw Error.selfTestFailed("socketpair：\(String(cString: strerror(errno)))")
        }
        defer { sockets.forEach { Darwin.close($0) } }
        let original = open("/dev/null", O_RDONLY)
        guard original >= 0 else {
            throw Error.selfTestFailed("打开自检描述符：\(String(cString: strerror(errno)))")
        }
        defer { Darwin.close(original) }

        try send(fileDescriptor: original, on: sockets[0])
        var payload: UInt8 = 0
        try withUnsafeMutablePointer(to: &payload) { payloadPointer in
            var io = iovec(iov_base: UnsafeMutableRawPointer(payloadPointer), iov_len: 1)
            try withUnsafeMutablePointer(to: &io) { ioPointer in
                var control = [UInt8](repeating: 0, count: CMSG_SPACE(2 * MemoryLayout<Int32>.size))
                try control.withUnsafeMutableBytes { controlRaw in
                    var message = msghdr()
                    message.msg_iov = ioPointer
                    message.msg_iovlen = 1
                    message.msg_control = controlRaw.baseAddress
                    message.msg_controllen = socklen_t(controlRaw.count)
                    guard recvmsg(sockets[1], &message, 0) == 1,
                          let header = CMSG_FIRSTHDR(&message),
                          header.pointee.cmsg_level == SOL_SOCKET,
                          header.pointee.cmsg_type == SCM_RIGHTS else {
                        throw Error.selfTestFailed("未收到 SCM_RIGHTS")
                    }
                    let headerLength = CMSG_ALIGN(MemoryLayout<cmsghdr>.size)
                    let available = max(0, min(Int(header.pointee.cmsg_len),
                                               Int(message.msg_controllen)) - headerLength)
                    let count = available / MemoryLayout<Int32>.size
                    let fds = (0..<count).map {
                        CMSG_DATA(header).load(fromByteOffset: $0 * MemoryLayout<Int32>.size,
                                               as: Int32.self)
                    }
                    defer { fds.forEach { Darwin.close($0) } }
                    guard count == 1, header.pointee.cmsg_len == CMSG_LEN(MemoryLayout<Int32>.size),
                          message.msg_flags & MSG_CTRUNC == 0,
                          sameFile(original, fds[0]) else {
                        throw Error.selfTestFailed("发送端未准确传递一个原始描述符")
                    }
                }
            }
        }

        try send(fileDescriptor: original, on: sockets[0])
        let received = try receive(on: sockets[1])
        defer { Darwin.close(received) }
        guard sameFile(original, received) else {
            throw Error.selfTestFailed("接收端取得的描述符不是原始文件")
        }
    }

    private static func sameFile(_ original: Int32, _ received: Int32) -> Bool {
        var source = stat()
        var target = stat()
        return fstat(original, &source) == 0 && fstat(received, &target) == 0 &&
            source.st_dev == target.st_dev && source.st_ino == target.st_ino &&
            source.st_rdev == target.st_rdev
    }
}

// MARK: - Darwin CMSG helpers
// Swift cannot import the CMSG_* macros directly on every SDK. Darwin's
// CMSG_* macros use __DARWIN_ALIGN32 (4 bytes) even in 64-bit processes;
// aligning by MemoryLayout<Int>.size (8 on x86_64/arm64) adds a phantom fd 0.

private func CMSG_ALIGN(_ length: Int) -> Int {
    let alignment = MemoryLayout<UInt32>.size
    return (length + alignment - 1) & ~(alignment - 1)
}

private func CMSG_LEN(_ length: Int) -> Int {
    CMSG_ALIGN(MemoryLayout<cmsghdr>.size) + length
}

private func CMSG_SPACE(_ length: Int) -> Int {
    CMSG_ALIGN(MemoryLayout<cmsghdr>.size) + CMSG_ALIGN(length)
}

private func CMSG_FIRSTHDR(_ message: UnsafeMutablePointer<msghdr>) -> UnsafeMutablePointer<cmsghdr>? {
    let length = Int(message.pointee.msg_controllen)
    guard length >= MemoryLayout<cmsghdr>.size, let control = message.pointee.msg_control else {
        return nil
    }
    return control.assumingMemoryBound(to: cmsghdr.self)
}

private func CMSG_DATA(_ header: UnsafeMutablePointer<cmsghdr>) -> UnsafeMutableRawPointer {
    UnsafeMutableRawPointer(header).advanced(by: CMSG_ALIGN(MemoryLayout<cmsghdr>.size))
}
