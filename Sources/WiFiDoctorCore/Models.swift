import Foundation

/// Security classification for a Wi-Fi network.
public enum WiFiSecurityLevel: String, Sendable, Codable, CaseIterable {
    case open = "Open (None)"
    case wep = "WEP"
    case wpaPersonal = "WPA Personal"
    case wpa2Personal = "WPA2 Personal"
    case wpa3Personal = "WPA3 Personal"
    case wpaEnterprise = "WPA/WPA2/WPA3 Enterprise"
    case unknown = "Unknown"

    /// Whether this security mode is considered weak or legacy.
    public var isWeak: Bool {
        switch self {
        case .open, .wep, .wpaPersonal:
            return true
        case .wpa2Personal, .wpa3Personal, .wpaEnterprise, .unknown:
            return false
        }
    }
}

/// Snapshot of a Wi-Fi network (either the active connection or a scanned neighbor).
public struct WiFiNetworkInfo: Identifiable, Hashable, Sendable {
    public var id: String { "\(ssid ?? "<hidden>")-\(bssid ?? "unknown")-\(channel)" }
    public let ssid: String?
    public let bssid: String?
    public let rssi: Int
    public let noise: Int
    public let channel: Int
    public let band: String
    public let security: WiFiSecurityLevel
    public let transmitRateMbps: Double?
    public let isCurrent: Bool

    public var snr: Int { rssi - noise }

    public var displayName: String {
        if let ssid, !ssid.isEmpty {
            return ssid
        }
        return "<Hidden or Redacted SSID>"
    }

    public init(
        ssid: String?,
        bssid: String?,
        rssi: Int,
        noise: Int,
        channel: Int,
        band: String,
        security: WiFiSecurityLevel,
        transmitRateMbps: Double? = nil,
        isCurrent: Bool = false
    ) {
        self.ssid = ssid
        self.bssid = bssid
        self.rssi = rssi
        self.noise = noise
        self.channel = channel
        self.band = band
        self.security = security
        self.transmitRateMbps = transmitRateMbps
        self.isCurrent = isCurrent
    }
}

/// Severity level for a network security or health finding.
public enum AuditSeverity: String, Sendable, Comparable {
    case pass = "Pass"
    case warning = "Warning"
    case critical = "Critical"

    private var rank: Int {
        switch self {
        case .pass: return 0
        case .warning: return 1
        case .critical: return 2
        }
    }

    public static func < (lhs: AuditSeverity, rhs: AuditSeverity) -> Bool {
        lhs.rank < rhs.rank
    }
}

/// A single diagnostic or security audit finding with remediation guidance.
public struct AuditFinding: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let severity: AuditSeverity
    public let title: String
    public let detail: String
    public let recommendation: String

    public init(
        id: UUID = UUID(),
        severity: AuditSeverity,
        title: String,
        detail: String,
        recommendation: String
    ) {
        self.id = id
        self.severity = severity
        self.title = title
        self.detail = detail
        self.recommendation = recommendation
    }
}

/// Result of an ICMP ping probe.
public struct PingResult: Sendable, Equatable {
    public let host: String
    public let transmitted: Int
    public let received: Int
    public let packetLossPercent: Double
    public let minMs: Double?
    public let avgMs: Double?
    public let maxMs: Double?
    public let rawOutput: String
    public let errorMessage: String?

    public var isReachable: Bool { received > 0 }
}

/// Result of a DNS resolution timing check.
public struct DNSLookupResult: Sendable, Equatable {
    public let hostname: String
    public let resolvedAddresses: [String]
    public let durationMs: Double
    public let errorMessage: String?
}

/// Captive portal / HTTP connectivity check status.
public enum CaptivePortalStatus: Sendable, Equatable {
    case online
    case captivePortalDetected(redirectURL: String?)
    case offline(reason: String)
}

/// Combined network diagnostic report.
public struct DiagnosticReport: Sendable {
    public let interfaceName: String?
    public let localIPv4: String?
    public let gatewayIP: String?
    public let dnsServers: [String]
    public let gatewayPing: PingResult?
    public let externalPing: PingResult?
    public let dnsLookup: DNSLookupResult?
    public let captivePortal: CaptivePortalStatus
    public let timestamp: Date
}

/// Reachability status for a probed TCP port.
public enum PortStatus: String, Sendable, Equatable {
    case open = "Open"
    case closed = "Closed / Refused"
    case timedOut = "Filtered / Timed Out"
}

/// Result of checking a single TCP port on a target host.
public struct PortCheckResult: Identifiable, Sendable, Equatable {
    public var id: Int { port }
    public let host: String
    public let port: Int
    public let serviceName: String
    public let status: PortStatus
    public let latencyMs: Double?
    public let securityNote: String?
}
