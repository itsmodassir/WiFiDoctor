import Foundation
import Network

/// Checks TCP port reachability on a local gateway or target host using Network.framework.
public struct PortCheckService: Sendable {
    public static let defaultPorts: [Int] = [21, 22, 23, 53, 80, 443, 445, 548, 8080, 8443]
    public static let routerSecurityPorts: [Int] = [21, 22, 23, 53, 80, 443, 445, 548, 1900, 3389, 5000, 5900, 7547, 8080, 8443]

    public init() {}

    /// Parses a comma-separated port list or ranges (e.g., "22, 80, 443, 8000-8005") into valid sorted unique ports.
    public static func parsePortList(_ input: String) -> [Int] {
        var collected: [Int] = []
        for rawToken in input.split(separator: ",") {
            let token = rawToken.trimmingCharacters(in: .whitespaces)
            if token.contains("-") {
                let bounds = token.split(separator: "-").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
                if bounds.count == 2, bounds[0] <= bounds[1], (1...65535).contains(bounds[0]), (1...65535).contains(bounds[1]) {
                    let upper = min(bounds[1], bounds[0] + 100)
                    collected.append(contentsOf: bounds[0]...upper)
                }
            } else if let single = Int(token), (1...65535).contains(single) {
                collected.append(single)
            }
        }
        return Array(Set(collected)).sorted()
    }

    /// Maps well-known port numbers to service labels and hardening notes.
    public static func serviceMetadata(for port: Int) -> (name: String, insecureNote: String?) {
        switch port {
        case 21: return ("FTP", "Plaintext FTP exposed; disable or use SFTP.")
        case 22: return ("SSH", nil)
        case 23: return ("Telnet", "Unencrypted Telnet exposed; disable immediately and use SSH.")
        case 53: return ("DNS", nil)
        case 80: return ("HTTP", "Unencrypted HTTP management/web port open; prefer HTTPS (443).")
        case 443: return ("HTTPS", nil)
        case 445: return ("SMB", "File sharing (SMB) reachable; ensure strong auth and LAN-only firewalling.")
        case 548: return ("AFP", nil)
        case 1900: return ("UPnP/SSDP", "UPnP enabled; disable on router if not required to prevent automatic port-opening.")
        case 3389: return ("RDP", "Remote Desktop exposed; restrict to VPN or trusted LAN hosts.")
        case 5000: return ("UPnP/HTTP", "Common UPnP/admin port open; verify if intentional.")
        case 5900: return ("VNC", "VNC screen sharing exposed; require strong password or SSH tunnel.")
        case 7547: return ("TR-069", "ISP remote management (CWMP) port open; ensure it is not exposed on WAN.")
        case 8080: return ("HTTP-Alt", "Alternative HTTP port open; verify if admin UI should be HTTPS-only.")
        case 8443: return ("HTTPS-Alt", nil)
        default: return ("TCP/\(port)", nil)
        }
    }

    /// Probes the specified TCP ports on `host` concurrently.
    public func checkPorts(host: String, ports: [Int], timeoutSeconds: Double = 2.0) async -> [PortCheckResult] {
        await withTaskGroup(of: PortCheckResult.self) { group in
            for port in ports {
                group.addTask {
                    await Self.probePort(host: host, port: port, timeoutSeconds: timeoutSeconds)
                }
            }

            var results: [PortCheckResult] = []
            for await item in group {
                results.append(item)
            }
            return results.sorted { $0.port < $1.port }
        }
    }

    private static func probePort(host: String, port: Int, timeoutSeconds: Double) async -> PortCheckResult {
        let meta = serviceMetadata(for: port)
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            return PortCheckResult(
                host: host,
                port: port,
                serviceName: meta.name,
                status: .closed,
                latencyMs: nil,
                securityNote: nil
            )
        }

        final class Gate: @unchecked Sendable {
            private let lock = NSLock()
            private var done = false
            func tryComplete() -> Bool {
                lock.lock()
                defer { lock.unlock() }
                if done { return false }
                done = true
                return true
            }
        }

        let start = DispatchTime.now().uptimeNanoseconds
        let endpointHost = NWEndpoint.Host(host)
        let connection = NWConnection(host: endpointHost, port: nwPort, using: .tcp)
        let queue = DispatchQueue(label: "wifidoctor.portcheck.\(port)")
        let gate = Gate()

        let status: (PortStatus, Double?) = await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if gate.tryComplete() {
                        let ms = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000.0
                        connection.cancel()
                        continuation.resume(returning: (.open, ms))
                    }
                case .failed:
                    if gate.tryComplete() {
                        connection.cancel()
                        continuation.resume(returning: (.closed, nil))
                    }
                case .waiting:
                    // Often indicates unreachable/refused on local LAN
                    break
                default:
                    break
                }
            }

            connection.start(queue: queue)

            queue.asyncAfter(deadline: .now() + timeoutSeconds) {
                if gate.tryComplete() {
                    connection.cancel()
                    continuation.resume(returning: (.timedOut, nil))
                }
            }
        }

        return PortCheckResult(
            host: host,
            port: port,
            serviceName: meta.name,
            status: status.0,
            latencyMs: status.1,
            securityNote: status.0 == .open ? meta.insecureNote : nil
        )
    }
}
