import Foundation
import Security

// MARK: - Channel Congestion Analyzer

public struct ChannelUsage: Identifiable, Sendable, Equatable {
    public var id: String { "\(band)-\(channel)" }
    public let band: String
    public let channel: Int
    public let networkCount: Int
    public let strongestRSSI: Int?
    public let ssids: [String]
}

public struct ChannelRecommendation: Sendable, Equatable {
    public let band: String
    public let recommendedChannel: Int
    public let reason: String
}

public struct ChannelAnalyzer: Sendable {
    public init() {}

    public func analyze(networks: [WiFiNetworkInfo]) -> (usage: [ChannelUsage], recommendations: [ChannelRecommendation]) {
        var grouped: [String: [WiFiNetworkInfo]] = [:]
        for net in networks where net.channel > 0 {
            let key = "\(net.band)|\(net.channel)"
            grouped[key, default: []].append(net)
        }

        var usage: [ChannelUsage] = []
        for (key, nets) in grouped {
            let parts = key.split(separator: "|")
            let band = String(parts[0])
            let channel = Int(parts[1]) ?? 0
            usage.append(
                ChannelUsage(
                    band: band,
                    channel: channel,
                    networkCount: nets.count,
                    strongestRSSI: nets.map(\.rssi).max(),
                    ssids: nets.map(\.displayName)
                )
            )
        }

        usage.sort {
            if $0.band != $1.band { return $0.band < $1.band }
            return $0.channel < $1.channel
        }

        var recs: [ChannelRecommendation] = []

        // Recommend best non-overlapping 2.4 GHz channel (1, 6, 11)
        let twoFourCounts = [1, 6, 11].map { ch in
            (ch, networks.filter { $0.band == "2.4 GHz" && $0.channel == ch }.count)
        }
        if let best24 = twoFourCounts.min(by: { $0.1 < $1.1 }) {
            recs.append(
                ChannelRecommendation(
                    band: "2.4 GHz",
                    recommendedChannel: best24.0,
                    reason: "Least congested non-overlapping 2.4 GHz channel (\(best24.1) AP(s) detected on ch \(best24.0))."
                )
            )
        }

        // Recommend best common 5 GHz channel
        let fiveCandidates = [36, 40, 44, 48, 149, 153, 157, 161]
        let fiveCounts = fiveCandidates.map { ch in
            (ch, networks.filter { $0.band == "5 GHz" && $0.channel == ch }.count)
        }
        if let best5 = fiveCounts.min(by: { $0.1 < $1.1 }) {
            recs.append(
                ChannelRecommendation(
                    band: "5 GHz",
                    recommendedChannel: best5.0,
                    reason: "Least congested 5 GHz channel (\(best5.1) AP(s) detected on ch \(best5.0))."
                )
            )
        }

        return (usage, recs)
    }
}

// MARK: - DNS Security & DoH Check

public struct DNSSecurityResult: Sendable, Equatable {
    public let testDomain: String
    public let localAddresses: [String]
    public let dohAddresses: [String]
    public let dohReachable: Bool
    public let hasMismatch: Bool
    public let summary: String
}

public struct DNSSecurityService: Sendable {
    public init() {}

    /// Compares local system DNS resolution against Cloudflare DNS-over-HTTPS (1.1.1.1).
    public func checkDNSSecurity(domain: String = "example.com") async -> DNSSecurityResult {
        async let localLookup = DiagnosticsService.measureDNSLookup(hostname: domain)
        async let dohLookup = queryCloudflareDoH(domain: domain)

        let local = await localLookup
        let doh = await dohLookup

        let localSet = Set(local.resolvedAddresses)
        let dohSet = Set(doh.addresses)

        let mismatch: Bool
        let summary: String
        if !doh.reachable {
            mismatch = false
            summary = "DNS-over-HTTPS (1.1.1.1) is unreachable or blocked on this network."
        } else if localSet.isEmpty {
            mismatch = true
            summary = "Local DNS failed to resolve \(domain), while DoH succeeded."
        } else if localSet.intersection(dohSet).isEmpty {
            mismatch = true
            summary = "Local DNS returned \(local.resolvedAddresses.joined(separator: ", ")) which differs from DoH (\(doh.addresses.joined(separator: ", "))). Possible DNS interception or split-horizon DNS."
        } else {
            mismatch = false
            summary = "Local DNS matches encrypted DoH (1.1.1.1) and DoH is reachable."
        }

        return DNSSecurityResult(
            testDomain: domain,
            localAddresses: local.resolvedAddresses,
            dohAddresses: doh.addresses,
            dohReachable: doh.reachable,
            hasMismatch: mismatch,
            summary: summary
        )
    }

    private func queryCloudflareDoH(domain: String) async -> (reachable: Bool, addresses: [String]) {
        guard var comps = URLComponents(string: "https://cloudflare-dns.com/dns-query") else {
            return (false, [])
        }
        comps.queryItems = [
            URLQueryItem(name: "name", value: domain),
            URLQueryItem(name: "type", value: "A")
        ]
        guard let url = comps.url else { return (false, []) }

        var req = URLRequest(url: url)
        req.setValue("application/dns-json", forHTTPHeaderField: "Accept")
        req.timeoutInterval = 5.0

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return (false, [])
            }
            if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
               let answers = json["Answer"] as? [[String: Any]] {
                let ips = answers.compactMap { ans -> String? in
                    guard (ans["type"] as? Int) == 1 else { return nil }
                    return ans["data"] as? String
                }
                return (true, ips)
            }
            return (true, [])
        } catch {
            return (false, [])
        }
    }
}

// MARK: - TLS & HTTP Security Header Inspector

public struct TLSInspectionResult: Sendable, Equatable {
    public let urlString: String
    public let statusCode: Int?
    public let isHTTPS: Bool
    public let certificateSubject: String?
    public let certificateTrusted: Bool
    public let securityHeadersPresent: [String]
    public let missingSecurityHeaders: [String]
    public let errorMessage: String?
}

public struct TLSInspectorService: Sendable {
    public static let recommendedHeaders = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy"
    ]

    public init() {}

    public func inspect(urlString: String) async -> TLSInspectionResult {
        var normalized = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        if !normalized.contains("://") {
            normalized = "https://\(normalized)"
        }
        guard let url = URL(string: normalized) else {
            return TLSInspectionResult(
                urlString: normalized,
                statusCode: nil,
                isHTTPS: false,
                certificateSubject: nil,
                certificateTrusted: false,
                securityHeadersPresent: [],
                missingSecurityHeaders: Self.recommendedHeaders,
                errorMessage: "Invalid URL"
            )
        }

        let isHTTPS = url.scheme?.lowercased() == "https"
        final class Delegate: NSObject, URLSessionDelegate, @unchecked Sendable {
            var subject: String?
            var trusted: Bool = true
            func urlSession(
                _ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
            ) {
                if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                   let trust = challenge.protectionSpace.serverTrust {
                    if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                       let leaf = chain.first {
                        subject = SecCertificateCopySubjectSummary(leaf) as String?
                    }
                    var err: CFError?
                    trusted = SecTrustEvaluateWithError(trust, &err)
                    completionHandler(.useCredential, URLCredential(trust: trust))
                    return
                }
                completionHandler(.performDefaultHandling, nil)
            }
        }

        let delegate = Delegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        var request = URLRequest(url: url)
        request.timeoutInterval = 6.0

        do {
            let (_, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                return TLSInspectionResult(
                    urlString: normalized,
                    statusCode: nil,
                    isHTTPS: isHTTPS,
                    certificateSubject: delegate.subject,
                    certificateTrusted: delegate.trusted,
                    securityHeadersPresent: [],
                    missingSecurityHeaders: Self.recommendedHeaders,
                    errorMessage: "Non-HTTP response"
                )
            }

            let headerKeys = Set(http.allHeaderFields.keys.map { String(describing: $0).lowercased() })
            var present: [String] = []
            var missing: [String] = []
            for h in Self.recommendedHeaders {
                if headerKeys.contains(h.lowercased()) {
                    present.append(h)
                } else {
                    missing.append(h)
                }
            }

            return TLSInspectionResult(
                urlString: normalized,
                statusCode: http.statusCode,
                isHTTPS: isHTTPS,
                certificateSubject: delegate.subject,
                certificateTrusted: isHTTPS ? delegate.trusted : false,
                securityHeadersPresent: present,
                missingSecurityHeaders: missing,
                errorMessage: nil
            )
        } catch {
            return TLSInspectionResult(
                urlString: normalized,
                statusCode: nil,
                isHTTPS: isHTTPS,
                certificateSubject: delegate.subject,
                certificateTrusted: false,
                securityHeadersPresent: [],
                missingSecurityHeaders: Self.recommendedHeaders,
                errorMessage: error.localizedDescription
            )
        }
    }
}

// MARK: - LAN Device Inventory (ARP Table)

public struct LANDevice: Identifiable, Sendable, Equatable {
    public var id: String { "\(ip)-\(mac)" }
    public let hostname: String
    public let ip: String
    public let mac: String
    public let interfaceName: String
}

public struct LANDiscoveryService: Sendable {
    public init() {}

    public func discoverARPDevices() -> [LANDevice] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
        process.arguments = ["-a"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        guard (try? process.run()) != nil else { return [] }
        process.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return Self.parseARPOutput(out)
    }

    public static func parseARPOutput(_ output: String) -> [LANDevice] {
        var devices: [LANDevice] = []
        for line in output.components(separatedBy: .newlines) {
            // Format: host (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
            guard let openParen = line.firstIndex(of: "("),
                  let closeParen = line.firstIndex(of: ")"),
                  openParen < closeParen else { continue }

            let hostname = line[..<openParen].trimmingCharacters(in: .whitespaces)
            let ip = String(line[line.index(after: openParen)..<closeParen])

            if ip.hasPrefix("224.") || ip.hasPrefix("239.") || ip.hasSuffix(".255") || ip == "255.255.255.255" {
                continue
            }

            let rest = String(line[line.index(after: closeParen)...])
            let tokens = rest.split(separator: " ").map(String.init)
            var mac = "incomplete"
            var iface = "en0"
            if let atIdx = tokens.firstIndex(of: "at"), atIdx + 1 < tokens.count {
                mac = tokens[atIdx + 1]
            }
            if let onIdx = tokens.firstIndex(of: "on"), onIdx + 1 < tokens.count {
                iface = tokens[onIdx + 1]
            }
            if mac == "(incomplete)" { continue }

            devices.append(
                LANDevice(
                    hostname: hostname == "?" ? "Unknown" : hostname,
                    ip: ip,
                    mac: mac,
                    interfaceName: iface
                )
            )
        }
        return devices
    }
}

// MARK: - Markdown Audit Report Exporter

public enum AuditReportExporter {
    public static func generateMarkdown(
        currentNetwork: WiFiNetworkInfo?,
        findings: [AuditFinding],
        channelRecommendations: [ChannelRecommendation],
        lanDevices: [LANDevice],
        dnsSecurity: DNSSecurityResult?,
        portResults: [PortCheckResult]
    ) -> String {
        var lines: [String] = []
        lines.append("# WiFiDoctor Security & Network Audit Report")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("")

        if let net = currentNetwork {
            lines.append("## Active Wi-Fi Connection")
            lines.append("- **SSID:** \(net.displayName)")
            lines.append("- **BSSID:** \(net.bssid ?? "Redacted")")
            lines.append("- **Security:** \(net.security.rawValue)")
            lines.append("- **Channel:** \(net.channel) (\(net.band))")
            lines.append("- **Signal / Noise:** \(net.rssi) dBm / \(net.noise) dBm (SNR \(net.snr) dB)")
            lines.append("")
        }

        lines.append("## Security Posture Findings (\(findings.count))")
        for f in findings {
            lines.append("- **[\(f.severity.rawValue.uppercased())] \(f.title)**: \(f.detail) _Fix: \(f.recommendation)_")
        }
        lines.append("")

        if !channelRecommendations.isEmpty {
            lines.append("## Channel Recommendations")
            for rec in channelRecommendations {
                lines.append("- **\(rec.band) → Channel \(rec.recommendedChannel):** \(rec.reason)")
            }
            lines.append("")
        }

        if let dnsSecurity {
            lines.append("## DNS Security Check (\(dnsSecurity.testDomain))")
            lines.append("- **Status:** \(dnsSecurity.summary)")
            lines.append("")
        }

        if !portResults.isEmpty {
            let openPorts = portResults.filter { $0.status == .open }
            lines.append("## Open Ports (\(openPorts.count) of \(portResults.count) checked)")
            for p in openPorts {
                lines.append("- **\(p.host):\(p.port) (\(p.serviceName))**\(p.securityNote.map { " — ⚠️ \($0)" } ?? "")")
            }
            lines.append("")
        }

        if !lanDevices.isEmpty {
            lines.append("## LAN Devices (ARP Table: \(lanDevices.count))")
            for d in lanDevices {
                lines.append("- `\(d.ip)` — \(d.hostname) (`\(d.mac)` on `\(d.interfaceName)`)")
            }
            lines.append("")
        }

        return lines.joined(separator: "\n")
    }
}
