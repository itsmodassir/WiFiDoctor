import Foundation

/// Evaluates Wi-Fi connection and scan results for configuration weaknesses and RF health issues.
public struct SecurityAuditService: Sendable {
    public init() {}

    /// Runs a security and RF health audit against the active Wi-Fi connection and nearby networks.
    public func audit(
        current: WiFiNetworkInfo?,
        nearby: [WiFiNetworkInfo]
    ) -> [AuditFinding] {
        var findings: [AuditFinding] = []

        if let current {
            findings.append(contentsOf: auditCurrentNetwork(current))
        } else {
            findings.append(
                AuditFinding(
                    severity: .warning,
                    title: "No Active Wi-Fi Connection",
                    detail: "Wi-Fi is disconnected or interface status is unavailable.",
                    recommendation: "Connect to a Wi-Fi network to audit its active security and RF health."
                )
            )
        }

        findings.append(contentsOf: auditNearbyDuplicates(nearby: nearby, current: current))
        findings.append(contentsOf: auditWeakNearbyNetworks(nearby: nearby))

        return findings.sorted { $0.severity > $1.severity }
    }

    private func auditCurrentNetwork(_ current: WiFiNetworkInfo) -> [AuditFinding] {
        var results: [AuditFinding] = []

        switch current.security {
        case .open:
            results.append(
                AuditFinding(
                    severity: .critical,
                    title: "Unencrypted Open Wi-Fi (\(current.displayName))",
                    detail: "Traffic on this network is not encrypted at the Wi-Fi layer.",
                    recommendation: "Enable WPA3-Personal or WPA2-AES (CCMP) on the access point, or use a VPN for all traffic."
                )
            )
        case .wep:
            results.append(
                AuditFinding(
                    severity: .critical,
                    title: "Legacy WEP Encryption (\(current.displayName))",
                    detail: "WEP is cryptographically broken and provides no meaningful confidentiality.",
                    recommendation: "Reconfigure the router/AP to use WPA3-SAE or WPA2-AES (CCMP)."
                )
            )
        case .wpaPersonal:
            results.append(
                AuditFinding(
                    severity: .warning,
                    title: "Legacy WPA/TKIP Security (\(current.displayName))",
                    detail: "WPA1 / TKIP has known weaknesses and limits modern Wi-Fi throughput.",
                    recommendation: "Switch the AP security mode to WPA2-AES or WPA3."
                )
            )
        case .wpa2Personal, .wpa3Personal, .wpaEnterprise:
            results.append(
                AuditFinding(
                    severity: .pass,
                    title: "Strong Wi-Fi Encryption (\(current.security.rawValue))",
                    detail: "Connected to \(current.displayName) using \(current.security.rawValue).",
                    recommendation: "No encryption change needed. Prefer WPA3-SAE where all client devices support it."
                )
            )
        case .unknown:
            results.append(
                AuditFinding(
                    severity: .warning,
                    title: "Unknown Security Mode (\(current.displayName))",
                    detail: "macOS did not report a recognized security profile for this connection.",
                    recommendation: "Verify the access point's wireless security settings directly in its admin console."
                )
            )
        }

        // RF / SNR health check
        if current.snr < 15 {
            results.append(
                AuditFinding(
                    severity: .warning,
                    title: "Low Signal-to-Noise Ratio (SNR \(current.snr) dB)",
                    detail: "RSSI is \(current.rssi) dBm with noise at \(current.noise) dBm on channel \(current.channel) (\(current.band)).",
                    recommendation: "Move closer to the access point, reduce interference, or switch to a less congested 5 GHz / 6 GHz channel."
                )
            )
        } else {
            results.append(
                AuditFinding(
                    severity: .pass,
                    title: "Healthy Signal-to-Noise Ratio (SNR \(current.snr) dB)",
                    detail: "RSSI \(current.rssi) dBm / Noise \(current.noise) dBm on channel \(current.channel) (\(current.band)).",
                    recommendation: "RF link quality is within healthy operating margins."
                )
            )
        }

        return results
    }

    private func auditNearbyDuplicates(
        nearby: [WiFiNetworkInfo],
        current: WiFiNetworkInfo?
    ) -> [AuditFinding] {
        var bySSID: [String: [WiFiNetworkInfo]] = [:]
        for net in nearby {
            guard let ssid = net.ssid, !ssid.isEmpty else { continue }
            bySSID[ssid, default: []].append(net)
        }

        var findings: [AuditFinding] = []
        for (ssid, nets) in bySSID {
            let uniqueSecurity = Set(nets.map(\.security))
            if uniqueSecurity.count > 1 {
                let modes = uniqueSecurity.map(\.rawValue).sorted().joined(separator: ", ")
                let isActive = current?.ssid == ssid
                findings.append(
                    AuditFinding(
                        severity: isActive ? .critical : .warning,
                        title: "Mismatched Security Modes for SSID \"\(ssid)\"",
                        detail: "Multiple BSSIDs broadcast \"\(ssid)\" with differing security modes: \(modes).",
                        recommendation: "Verify all authorized access points for \"\(ssid)\" use identical security settings; an unexpected open/weak BSSID may indicate a misconfigured or rogue AP."
                    )
                )
            }
        }
        return findings
    }

    private func auditWeakNearbyNetworks(nearby: [WiFiNetworkInfo]) -> [AuditFinding] {
        let weak = nearby.filter { $0.security.isWeak && !$0.isCurrent }
        guard !weak.isEmpty else { return [] }

        let sample = weak.prefix(5).map { "\($0.displayName) (\($0.security.rawValue))" }.joined(separator: ", ")
        return [
            AuditFinding(
                severity: .warning,
                title: "\(weak.count) Nearby Network(s) Use Weak/Open Security",
                detail: "Detected: \(sample)\(weak.count > 5 ? ", ..." : "").",
                recommendation: "If any of these belong to your infrastructure, upgrade them to WPA2-AES or WPA3 and disable legacy guest/open SSIDs if unused."
            )
        ]
    }
}

// MARK: - Passphrase Policy & Entropy Checker

public enum PassphraseStrength: String, Sendable, Equatable {
    case invalid = "Invalid (< 8 chars)"
    case weak = "Weak"
    case fair = "Fair"
    case strong = "Strong"
    case veryStrong = "Very Strong"
}

public struct PassphraseEvaluation: Sendable, Equatable {
    public let length: Int
    public let entropyBits: Double
    public let strength: PassphraseStrength
    public let warnings: [String]
    public let recommendation: String
}

/// Evaluates a Wi-Fi passphrase locally against length, character-pool entropy, and common pattern policies.
public struct PassphraseAuditor: Sendable {
    private static let commonWeakTokens = [
        "password", "12345678", "123456789", "qwerty", "admin", "welcome", "letmein", "iloveyou", "abc123"
    ]

    public init() {}

    public func evaluate(_ passphrase: String) -> PassphraseEvaluation {
        let length = passphrase.count
        if length < 8 {
            return PassphraseEvaluation(
                length: length,
                entropyBits: 0,
                strength: .invalid,
                warnings: ["WPA2/WPA3 passphrases must be at least 8 characters long."],
                recommendation: "Use a random 16+ character passphrase mixing uppercase, lowercase, numbers, and symbols."
            )
        }

        let hasLower = passphrase.rangeOfCharacter(from: .lowercaseLetters) != nil
        let hasUpper = passphrase.rangeOfCharacter(from: .uppercaseLetters) != nil
        let hasDigit = passphrase.rangeOfCharacter(from: .decimalDigits) != nil
        let hasSymbol = passphrase.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) != nil

        var poolSize = 0
        if hasLower { poolSize += 26 }
        if hasUpper { poolSize += 26 }
        if hasDigit { poolSize += 10 }
        if hasSymbol { poolSize += 32 }
        poolSize = max(poolSize, 26)

        let entropyBits = Double(length) * log2(Double(poolSize))
        var warnings: [String] = []

        if length < 12 {
            warnings.append("Length is under 12 characters; short WPA2 passphrases are more susceptible to offline guessing.")
        }
        if Set(passphrase).count <= max(2, length / 4) {
            warnings.append("Contains high character repetition.")
        }
        let lowercased = passphrase.lowercased()
        if Self.commonWeakTokens.contains(where: { lowercased.contains($0) }) {
            warnings.append("Contains a common dictionary or default password pattern.")
        }
        if !(hasLower && hasUpper && hasDigit) {
            warnings.append("Mix uppercase, lowercase, numbers, and symbols to maximize keyspace.")
        }

        let strength: PassphraseStrength
        if !warnings.isEmpty && (entropyBits < 55 || length < 10 || Self.commonWeakTokens.contains(where: { lowercased.contains($0) })) {
            strength = .weak
        } else if entropyBits < 65 {
            strength = .fair
        } else if entropyBits < 90 {
            strength = .strong
        } else {
            strength = .veryStrong
        }

        let recommendation: String = switch strength {
        case .invalid, .weak:
            "Replace with a 16+ character random passphrase (or 4+ random words) and enable WPA3-SAE if supported."
        case .fair:
            "Acceptable for basic use, but 16+ characters with symbols is recommended for client/enterprise Wi-Fi."
        case .strong, .veryStrong:
            "Meets strong Wi-Fi passphrase policy. Ensure WPA3-SAE or WPA2-AES (CCMP) is enabled on the access point."
        }

        return PassphraseEvaluation(
            length: length,
            entropyBits: entropyBits,
            strength: strength,
            warnings: warnings,
            recommendation: recommendation
        )
    }
}
