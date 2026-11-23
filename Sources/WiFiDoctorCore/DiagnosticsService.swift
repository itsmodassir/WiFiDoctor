import Foundation

/// Runs connectivity, gateway, ping latency, DNS timing, and captive portal diagnostics.
public struct DiagnosticsService: Sendable {
    public init() {}

    /// Runs a full suite of network diagnostics.
    public func runDiagnostics(
        interfaceName: String? = nil,
        externalPingHost: String = "1.1.1.1",
        dnsTestHost: String = "apple.com"
    ) async -> DiagnosticReport {
        let localIP = Self.detectLocalIPv4(interfaceName: interfaceName ?? "en0")
        let gatewayIP = Self.detectDefaultGateway()
        let dnsServers = Self.detectDNSServers()

        async let gatewayPingTask: PingResult? = {
            if let gw = gatewayIP {
                return await Self.ping(host: gw, count: 4)
            }
            return nil
        }()

        async let externalPingTask = Self.ping(host: externalPingHost, count: 4)
        async let dnsTask = Self.measureDNSLookup(hostname: dnsTestHost)
        async let captiveTask = Self.checkCaptivePortal()

        let (gwPing, extPing, dnsResult, captiveStatus) = await (
            gatewayPingTask,
            externalPingTask,
            dnsTask,
            captiveTask
        )

        return DiagnosticReport(
            interfaceName: interfaceName,
            localIPv4: localIP,
            gatewayIP: gatewayIP,
            dnsServers: dnsServers,
            gatewayPing: gwPing,
            externalPing: extPing,
            dnsLookup: dnsResult,
            captivePortal: captiveStatus,
            timestamp: Date()
        )
    }

    /// Runs `/sbin/ping` and parses latency and packet loss statistics.
    public static func ping(host: String, count: Int = 4) async -> PingResult {
        let output = await runCommand(
            executable: "/sbin/ping",
            arguments: ["-c", "\(count)", "-W", "2000", host]
        )
        return parsePingOutput(host: host, output: output.stdout, stderr: output.stderr, exitCode: output.exitCode)
    }

    /// Parses standard macOS `/sbin/ping` output.
    public static func parsePingOutput(
        host: String,
        output: String,
        stderr: String = "",
        exitCode: Int32 = 0
    ) -> PingResult {
        var transmitted = 0
        var received = 0
        var loss = 100.0
        var minMs: Double?
        var avgMs: Double?
        var maxMs: Double?

        for line in output.components(separatedBy: .newlines) {
            if line.contains("packets transmitted"), line.contains("packets received") {
                // Example: 4 packets transmitted, 4 packets received, 0.0% packet loss
                let parts = line.components(separatedBy: ",")
                if parts.count >= 3 {
                    transmitted = Int(parts[0].trimmingCharacters(in: .whitespaces).components(separatedBy: " ").first ?? "") ?? 0
                    received = Int(parts[1].trimmingCharacters(in: .whitespaces).components(separatedBy: " ").first ?? "") ?? 0
                    let lossToken = parts[2].trimmingCharacters(in: .whitespaces).components(separatedBy: "%").first ?? ""
                    loss = Double(lossToken) ?? 100.0
                }
            } else if line.contains("round-trip min/avg/max/stddev") {
                // Example: round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms
                if let eqRange = line.range(of: "=") {
                    let statsPart = line[eqRange.upperBound...]
                        .replacingOccurrences(of: "ms", with: "")
                        .trimmingCharacters(in: .whitespaces)
                    let nums = statsPart.components(separatedBy: "/").compactMap { Double($0) }
                    if nums.count >= 3 {
                        minMs = nums[0]
                        avgMs = nums[1]
                        maxMs = nums[2]
                    }
                }
            }
        }

        let err: String?
        if exitCode != 0 && received == 0 {
            err = stderr.isEmpty ? "Host unreachable or timed out." : stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            err = nil
        }

        return PingResult(
            host: host,
            transmitted: transmitted,
            received: received,
            packetLossPercent: loss,
            minMs: minMs,
            avgMs: avgMs,
            maxMs: maxMs,
            rawOutput: output,
            errorMessage: err
        )
    }

    public static func detectDefaultGateway() -> String? {
        let res = runCommandSync(executable: "/sbin/route", arguments: ["-n", "get", "default"])
        return parseGatewayOutput(res.stdout)
    }

    public static func parseGatewayOutput(_ output: String) -> String? {
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("gateway:") {
                let value = trimmed.replacingOccurrences(of: "gateway:", with: "")
                    .trimmingCharacters(in: .whitespaces)
                return value.isEmpty ? nil : value
            }
        }
        return nil
    }

    public static func detectDNSServers() -> [String] {
        let res = runCommandSync(executable: "/usr/sbin/scutil", arguments: ["--dns"])
        return parseDNSServers(res.stdout)
    }

    public static func parseDNSServers(_ output: String) -> [String] {
        var servers: [String] = []
        var seen = Set<String>()
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("nameserver[") {
                if let colonIdx = trimmed.firstIndex(of: ":") {
                    let ip = trimmed[trimmed.index(after: colonIdx)...].trimmingCharacters(in: .whitespaces)
                    if !ip.isEmpty && !seen.contains(ip) {
                        seen.insert(ip)
                        servers.append(ip)
                    }
                }
            }
        }
        return servers
    }

    public static func detectLocalIPv4(interfaceName: String) -> String? {
        let res = runCommandSync(executable: "/usr/sbin/ipconfig", arguments: ["getifaddr", interfaceName])
        let ip = res.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return (res.exitCode == 0 && !ip.isEmpty) ? ip : nil
    }

    /// Measures DNS lookup latency using `getaddrinfo`.
    public static func measureDNSLookup(hostname: String) async -> DNSLookupResult {
        await Task.detached(priority: .userInitiated) {
            let start = DispatchTime.now().uptimeNanoseconds
            var hints = addrinfo(
                ai_flags: 0,
                ai_family: AF_UNSPEC,
                ai_socktype: SOCK_STREAM,
                ai_protocol: 0,
                ai_addrlen: 0,
                ai_canonname: nil,
                ai_addr: nil,
                ai_next: nil
            )
            var resultPtr: UnsafeMutablePointer<addrinfo>?
            let status = getaddrinfo(hostname, nil, &hints, &resultPtr)
            let elapsedMs = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000.0

            if status != 0 {
                let message = String(cString: gai_strerror(status))
                return DNSLookupResult(
                    hostname: hostname,
                    resolvedAddresses: [],
                    durationMs: elapsedMs,
                    errorMessage: message
                )
            }

            defer {
                if let resultPtr { freeaddrinfo(resultPtr) }
            }

            var addresses: [String] = []
            var ptr = resultPtr
            while let current = ptr {
                var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if let addr = current.pointee.ai_addr {
                    let len = current.pointee.ai_addrlen
                    if getnameinfo(addr, len, &hostBuffer, socklen_t(hostBuffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                        let bytes = hostBuffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
                        let ip = String(decoding: bytes, as: UTF8.self)
                        if !addresses.contains(ip) {
                            addresses.append(ip)
                        }
                    }
                }
                ptr = current.pointee.ai_next
            }

            return DNSLookupResult(
                hostname: hostname,
                resolvedAddresses: addresses,
                durationMs: elapsedMs,
                errorMessage: nil
            )
        }.value
    }

    /// Checks Apple's standard captive portal endpoint to detect login redirects or offline state.
    public static func checkCaptivePortal() async -> CaptivePortalStatus {
        guard let url = URL(string: "http://captive.apple.com/hotspot-detect.html") else {
            return .offline(reason: "Invalid probe URL")
        }
        var request = URLRequest(url: url)
        request.timeoutInterval = 5.0
        request.cachePolicy = .reloadIgnoringLocalCacheData

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let body = String(data: data, encoding: .utf8) ?? ""
            if let http = response as? HTTPURLResponse {
                if http.statusCode == 200 && body.contains("Success") {
                    return .online
                }
                let finalURL = http.url?.absoluteString
                return .captivePortalDetected(redirectURL: finalURL)
            }
            return .online
        } catch {
            return .offline(reason: error.localizedDescription)
        }
    }

    private static func runCommand(executable: String, arguments: [String]) async -> (stdout: String, stderr: String, exitCode: Int32) {
        await Task.detached(priority: .userInitiated) {
            runCommandSync(executable: executable, arguments: arguments)
        }.value
    }

    private static func runCommandSync(executable: String, arguments: [String]) -> (stdout: String, stderr: String, exitCode: Int32) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        do {
            try process.run()
            process.waitUntilExit()
            let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            return (
                String(data: outData, encoding: .utf8) ?? "",
                String(data: errData, encoding: .utf8) ?? "",
                process.terminationStatus
            )
        } catch {
            return ("", error.localizedDescription, -1)
        }
    }
}
