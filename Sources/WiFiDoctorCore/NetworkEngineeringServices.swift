import Foundation

// MARK: - Traceroute / Hop Latency Analyzer

public struct TracerouteHop: Identifiable, Sendable, Equatable {
    public var id: Int { hopNumber }
    public let hopNumber: Int
    public let address: String
    public let rttMs: Double?
    public let timedOut: Bool
}

public struct TracerouteService: Sendable {
    public init() {}

    public func runTraceroute(host: String, maxHops: Int = 20) async -> [TracerouteHop] {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }

        return await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/traceroute")
            process.arguments = ["-n", "-w", "2", "-q", "1", "-m", "\(maxHops)", trimmed]

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = Pipe()

            guard (try? process.run()) != nil else { return [] }
            process.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            return Self.parseTracerouteOutput(output)
        }.value
    }

    public static func parseTracerouteOutput(_ output: String) -> [TracerouteHop] {
        var hops: [TracerouteHop] = []
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard let hopNum = Int(parts.first ?? "") else { continue }

            if parts.count >= 2 && parts[1] == "*" {
                hops.append(TracerouteHop(hopNumber: hopNum, address: "* (Request Timed Out)", rttMs: nil, timedOut: true))
                continue
            }

            let addr = parts.count >= 2 ? parts[1] : "Unknown"
            var rtt: Double?
            if let msIdx = parts.firstIndex(of: "ms"), msIdx > 0 {
                rtt = Double(parts[msIdx - 1])
            }
            hops.append(TracerouteHop(hopNumber: hopNum, address: addr, rttMs: rtt, timedOut: false))
        }
        return hops
    }
}

// MARK: - DHCP & Interface Configuration Inspector

public struct InterfaceConfigInfo: Sendable, Equatable {
    public let interfaceName: String
    public let macAddress: String?
    public let mtu: Int?
    public let ipv4Address: String?
    public let subnetMask: String?
    public let routerIP: String?
    public let dhcpServerIP: String?
    public let leaseTimeSeconds: Int?
    public let domainName: String?
}

public struct InterfaceInspectorService: Sendable {
    public init() {}

    public func inspect(interfaceName: String = "en0") -> InterfaceConfigInfo {
        let ifconfigOut = Self.runSync(executable: "/sbin/ifconfig", arguments: [interfaceName])
        let dhcpOut = Self.runSync(executable: "/usr/sbin/ipconfig", arguments: ["getpacket", interfaceName])
        return Self.parse(interfaceName: interfaceName, ifconfigOutput: ifconfigOut, dhcpPacketOutput: dhcpOut)
    }

    public static func parse(
        interfaceName: String,
        ifconfigOutput: String,
        dhcpPacketOutput: String
    ) -> InterfaceConfigInfo {
        var mac: String?
        var mtu: Int?
        var ipv4: String?

        for line in ifconfigOutput.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.contains("mtu ") {
                let tokens = trimmed.split(separator: " ").map(String.init)
                if let idx = tokens.firstIndex(of: "mtu"), idx + 1 < tokens.count {
                    mtu = Int(tokens[idx + 1])
                }
            } else if trimmed.hasPrefix("ether ") {
                mac = trimmed.replacingOccurrences(of: "ether ", with: "").trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("inet ") {
                let tokens = trimmed.split(separator: " ").map(String.init)
                if tokens.count >= 2 {
                    ipv4 = tokens[1]
                }
            }
        }

        var subnetMask: String?
        var routerIP: String?
        var dhcpServer: String?
        var leaseSeconds: Int?
        var domainName: String?

        for line in dhcpPacketOutput.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("yiaddr = ") {
                ipv4 = ipv4 ?? trimmed.replacingOccurrences(of: "yiaddr = ", with: "").trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("subnet_mask (ip): ") {
                subnetMask = trimmed.replacingOccurrences(of: "subnet_mask (ip): ", with: "").trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("router (ip_mult): ") {
                routerIP = trimmed.replacingOccurrences(of: "router (ip_mult): ", with: "")
                    .replacingOccurrences(of: "{", with: "")
                    .replacingOccurrences(of: "}", with: "")
                    .trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("server_identifier (ip): ") {
                dhcpServer = trimmed.replacingOccurrences(of: "server_identifier (ip): ", with: "").trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("lease_time (uint32): ") {
                let raw = trimmed.replacingOccurrences(of: "lease_time (uint32): ", with: "").trimmingCharacters(in: .whitespaces)
                if raw.hasPrefix("0x"), let val = Int(raw.dropFirst(2), radix: 16) {
                    leaseSeconds = val
                } else {
                    leaseSeconds = Int(raw)
                }
            } else if trimmed.hasPrefix("domain_name (string): ") {
                domainName = trimmed.replacingOccurrences(of: "domain_name (string): ", with: "").trimmingCharacters(in: .whitespaces)
            }
        }

        return InterfaceConfigInfo(
            interfaceName: interfaceName,
            macAddress: mac,
            mtu: mtu,
            ipv4Address: ipv4,
            subnetMask: subnetMask,
            routerIP: routerIP,
            dhcpServerIP: dhcpServer,
            leaseTimeSeconds: leaseSeconds,
            domainName: domainName
        )
    }

    private static func runSync(executable: String, arguments: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        guard (try? process.run()) != nil else { return "" }
        process.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    }
}
