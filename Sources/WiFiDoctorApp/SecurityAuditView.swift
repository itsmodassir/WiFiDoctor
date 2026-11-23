import SwiftUI
import WiFiDoctorCore

struct SecurityAuditView: View {
    @ObservedObject var wifiService: WiFiService
    @State private var findings: [AuditFinding] = []
    @State private var isRunning = false
    @State private var passphraseInput = ""
    @State private var revealPassphrase = false
    private let auditService = SecurityAuditService()
    private let passphraseAuditor = PassphraseAuditor()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Wi-Fi Security Posture Audit")
                        .font(.title2.bold())
                    Text("Checks encryption strength, duplicate/mismatched SSIDs, RF health, and passphrase policy.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task { await runAudit() }
                } label: {
                    if isRunning {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Run Audit", systemImage: "checkmark.shield")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isRunning)
            }

            GroupBox("Wi-Fi Passphrase Policy & Entropy Checker (Offline)") {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        if revealPassphrase {
                            TextField("Enter a Wi-Fi passphrase to check its strength", text: $passphraseInput)
                                .textFieldStyle(.roundedBorder)
                        } else {
                            SecureField("Enter a Wi-Fi passphrase to check its strength", text: $passphraseInput)
                                .textFieldStyle(.roundedBorder)
                        }
                        Toggle("Show", isOn: $revealPassphrase)
                            .toggleStyle(.checkbox)
                    }

                    if !passphraseInput.isEmpty {
                        let eval = passphraseAuditor.evaluate(passphraseInput)
                        HStack(spacing: 12) {
                            Text(eval.strength.rawValue.uppercased())
                                .font(.caption.bold())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(strengthColor(eval.strength).opacity(0.15), in: Capsule())
                                .foregroundStyle(strengthColor(eval.strength))
                            Text("Length: \(eval.length)")
                                .font(.caption)
                                .monospacedDigit()
                            Text(String(format: "Estimated Entropy: %.0f bits", eval.entropyBits))
                                .font(.caption)
                                .monospacedDigit()
                        }
                        ForEach(eval.warnings, id: \.self) { warning in
                            Label(warning, systemImage: "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                        Text(eval.recommendation)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            }

            if findings.isEmpty {
                ContentUnavailableView(
                    "No Audit Run Yet",
                    systemImage: "shield.lefthalf.filled",
                    description: Text("Click Run Audit to scan and evaluate your Wi-Fi environment.")
                )
            } else {
                List(findings) { finding in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            severityBadge(finding.severity)
                            Text(finding.title)
                                .font(.headline)
                        }
                        Text(finding.detail)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        Text("Fix: \(finding.recommendation)")
                            .font(.callout)
                            .foregroundStyle(.primary)
                    }
                    .padding(.vertical, 4)
                }
                .listStyle(.inset)
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task {
            if findings.isEmpty {
                await runAudit()
            }
        }
    }

    private func runAudit() async {
        isRunning = true
        defer { isRunning = false }
        if wifiService.scannedNetworks.isEmpty {
            await wifiService.scanNetworks()
        } else {
            wifiService.refreshCurrentConnection()
        }
        findings = auditService.audit(
            current: wifiService.currentNetwork,
            nearby: wifiService.scannedNetworks
        )
    }

    @ViewBuilder
    private func severityBadge(_ severity: AuditSeverity) -> some View {
        let color: Color = switch severity {
        case .critical: .red
        case .warning: .orange
        case .pass: .green
        }
        Text(severity.rawValue.uppercased())
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    private func strengthColor(_ strength: PassphraseStrength) -> Color {
        switch strength {
        case .invalid, .weak: return .red
        case .fair: return .orange
        case .strong: return .blue
        case .veryStrong: return .green
        }
    }
}
