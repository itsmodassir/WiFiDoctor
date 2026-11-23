import SwiftUI
import WiFiDoctorCore

struct DiagnosticsView: View {
    @ObservedObject var wifiService: WiFiService
    @State private var report: DiagnosticReport?
    @State private var isRunning = false
    @State private var externalHost = "1.1.1.1"
    @State private var dnsTestHost = "apple.com"
    private let service = DiagnosticsService()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Connectivity & Latency Diagnostics")
                        .font(.title2.bold())
                    Text("Tests gateway reachability, external ping, packet loss, DNS timing, and captive portals.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task { await runTests() }
                } label: {
                    if isRunning {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Run Diagnostics", systemImage: "play.fill")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isRunning)
            }

            HStack(spacing: 12) {
                LabeledContent("External Ping Host") {
                    TextField("1.1.1.1", text: $externalHost)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 150)
                }
                LabeledContent("DNS Test Domain") {
                    TextField("apple.com", text: $dnsTestHost)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 180)
                }
            }

            if let report {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        GroupBox("Interface & Routing") {
                            Grid(alignment: .leading, horizontalSpacing: 20, verticalSpacing: 6) {
                                GridRow {
                                    Text("Local IPv4:").foregroundStyle(.secondary)
                                    Text(report.localIPv4 ?? "Unavailable").monospaced()
                                }
                                GridRow {
                                    Text("Default Gateway:").foregroundStyle(.secondary)
                                    Text(report.gatewayIP ?? "Not Detected").monospaced()
                                }
                                GridRow {
                                    Text("DNS Servers:").foregroundStyle(.secondary)
                                    Text(report.dnsServers.isEmpty ? "None" : report.dnsServers.joined(separator: ", ")).monospaced()
                                }
                                GridRow {
                                    Text("Captive Portal:").foregroundStyle(.secondary)
                                    captiveLabel(report.captivePortal)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                        }

                        if let gwPing = report.gatewayPing {
                            pingCard(title: "Gateway Ping (\(gwPing.host))", ping: gwPing)
                        }

                        if let extPing = report.externalPing {
                            pingCard(title: "External Ping (\(extPing.host))", ping: extPing)
                        }

                        if let dns = report.dnsLookup {
                            GroupBox("DNS Resolution (\(dns.hostname))") {
                                VStack(alignment: .leading, spacing: 4) {
                                    if let err = dns.errorMessage {
                                        Label("DNS Error: \(err)", systemImage: "xmark.octagon.fill")
                                            .foregroundStyle(.red)
                                    } else {
                                        Text(String(format: "Lookup Time: %.1f ms", dns.durationMs))
                                            .bold()
                                            .monospacedDigit()
                                        Text("Resolved: \(dns.resolvedAddresses.joined(separator: ", "))")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .monospaced()
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(6)
                            }
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    "Ready to Test",
                    systemImage: "waveform.path.ecg",
                    description: Text("Click Run Diagnostics to measure latency, packet loss, and DNS resolution.")
                )
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func runTests() async {
        isRunning = true
        defer { isRunning = false }
        report = await service.runDiagnostics(
            interfaceName: wifiService.interfaceName,
            externalPingHost: externalHost,
            dnsTestHost: dnsTestHost
        )
    }

    @ViewBuilder
    private func captiveLabel(_ status: CaptivePortalStatus) -> some View {
        switch status {
        case .online:
            Label("Online (No Captive Portal)", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .captivePortalDetected(let redirectURL):
            Label("Captive Portal Detected (\(redirectURL ?? "Redirect"))", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        case .offline(let reason):
            Label("Offline (\(reason))", systemImage: "wifi.slash")
                .foregroundStyle(.red)
        }
    }

    private func pingCard(title: String, ping: PingResult) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 16) {
                    Text("Sent: \(ping.transmitted)")
                    Text("Received: \(ping.received)")
                    Text(String(format: "Loss: %.1f%%", ping.packetLossPercent))
                        .foregroundStyle(ping.packetLossPercent > 0 ? .orange : .green)
                    if let avg = ping.avgMs, let min = ping.minMs, let max = ping.maxMs {
                        Text(String(format: "RTT min/avg/max: %.1f / %.1f / %.1f ms", min, avg, max))
                            .monospacedDigit()
                    }
                }
                if let err = ping.errorMessage {
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }
}
