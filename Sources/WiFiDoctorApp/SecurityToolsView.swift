import AppKit
import SwiftUI
import UniformTypeIdentifiers
import WiFiDoctorCore

struct ChannelAnalyzerView: View {
    @ObservedObject var wifiService: WiFiService
    @State private var usage: [ChannelUsage] = []
    @State private var recommendations: [ChannelRecommendation] = []
    private let analyzer = ChannelAnalyzer()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Wi-Fi Channel Congestion Analyzer")
                        .font(.title2.bold())
                    Text("Finds crowded channels and recommends the cleanest 2.4 GHz & 5 GHz channels.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task {
                        await wifiService.scanNetworks()
                        analyze()
                    }
                } label: {
                    Label("Rescan & Analyze", systemImage: "antenna.radiowaves.left.and.right")
                }
                .buttonStyle(.borderedProminent)
                .disabled(wifiService.isScanning)
            }

            if !recommendations.isEmpty {
                GroupBox("Recommended Channels") {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(recommendations, id: \.band) { rec in
                            HStack(alignment: .top) {
                                Text("\(rec.band) → Ch \(rec.recommendedChannel)")
                                    .font(.headline)
                                    .foregroundStyle(.green)
                                    .frame(width: 150, alignment: .leading)
                                Text(rec.reason)
                                    .font(.callout)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
            }

            if usage.isEmpty {
                ContentUnavailableView(
                    "No Channel Data",
                    systemImage: "waveform",
                    description: Text("Click Rescan & Analyze to inspect nearby channel congestion.")
                )
            } else {
                Table(usage) {
                    TableColumn("Band") { item in Text(item.band) }
                    TableColumn("Channel") { item in
                        Text("\(item.channel)").monospacedDigit()
                    }
                    TableColumn("AP Count") { item in
                        Text("\(item.networkCount)")
                            .foregroundStyle(item.networkCount >= 3 ? .orange : .primary)
                            .monospacedDigit()
                    }
                    TableColumn("Strongest RSSI") { item in
                        Text(item.strongestRSSI.map { "\($0) dBm" } ?? "—")
                            .monospacedDigit()
                    }
                    TableColumn("SSIDs") { item in
                        Text(item.ssids.prefix(4).joined(separator: ", "))
                            .lineLimit(1)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { analyze() }
    }

    private func analyze() {
        let result = analyzer.analyze(networks: wifiService.scannedNetworks)
        usage = result.usage
        recommendations = result.recommendations
    }
}

struct DNSTLSInspectorView: View {
    @State private var dnsDomain = "example.com"
    @State private var dnsResult: DNSSecurityResult?
    @State private var isCheckingDNS = false

    @State private var tlsTarget = "https://\(DiagnosticsService.detectDefaultGateway() ?? "192.168.1.1")"
    @State private var tlsResult: TLSInspectionResult?
    @State private var isCheckingTLS = false

    private let dnsService = DNSSecurityService()
    private let tlsService = TLSInspectorService()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("DNS & TLS Security Inspector")
                        .font(.title2.bold())
                    Text("Checks for DNS interception against DoH (1.1.1.1) and inspects HTTPS certificates & security headers.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                GroupBox("DNS Consistency & DoH Reachability") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            TextField("Domain (e.g. example.com)", text: $dnsDomain)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 240)
                            Button {
                                Task {
                                    isCheckingDNS = true
                                    dnsResult = await dnsService.checkDNSSecurity(domain: dnsDomain)
                                    isCheckingDNS = false
                                }
                            } label: {
                                if isCheckingDNS {
                                    ProgressView().controlSize(.small)
                                } else {
                                    Label("Check DNS Security", systemImage: "lock.shield")
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(isCheckingDNS)
                        }

                        if let dnsResult {
                            Label(
                                dnsResult.summary,
                                systemImage: dnsResult.hasMismatch ? "exclamationmark.triangle.fill" : "checkmark.circle.fill"
                            )
                            .foregroundStyle(dnsResult.hasMismatch ? .orange : .green)
                            Text("Local DNS: \(dnsResult.localAddresses.isEmpty ? "None" : dnsResult.localAddresses.joined(separator: ", "))")
                                .font(.caption).monospaced()
                            Text("Cloudflare DoH: \(dnsResult.dohAddresses.isEmpty ? "Unavailable" : dnsResult.dohAddresses.joined(separator: ", "))")
                                .font(.caption).monospaced()
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                GroupBox("TLS Certificate & HTTP Security Headers") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            TextField("https://192.168.1.1 or https://example.com", text: $tlsTarget)
                                .textFieldStyle(.roundedBorder)
                            Button {
                                Task {
                                    isCheckingTLS = true
                                    tlsResult = await tlsService.inspect(urlString: tlsTarget)
                                    isCheckingTLS = false
                                }
                            } label: {
                                if isCheckingTLS {
                                    ProgressView().controlSize(.small)
                                } else {
                                    Label("Inspect TLS", systemImage: "checkmark.seal")
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(isCheckingTLS)
                        }

                        if let tlsResult {
                            if let err = tlsResult.errorMessage {
                                Label("Inspection Error: \(err)", systemImage: "xmark.octagon.fill")
                                    .foregroundStyle(.red)
                            } else {
                                HStack(spacing: 16) {
                                    Text("HTTP Status: \(tlsResult.statusCode.map(String.init) ?? "—")")
                                    Text("TLS Trusted: \(tlsResult.certificateTrusted ? "Yes" : "No / Self-Signed")")
                                        .foregroundStyle(tlsResult.certificateTrusted ? .green : .orange)
                                }
                                if let subject = tlsResult.certificateSubject {
                                    Text("Certificate Subject: \(subject)")
                                        .font(.caption).monospaced()
                                }
                                Text("Headers Present: \(tlsResult.securityHeadersPresent.isEmpty ? "None" : tlsResult.securityHeadersPresent.joined(separator: ", "))")
                                    .font(.caption)
                                    .foregroundStyle(.green)
                                if !tlsResult.missingSecurityHeaders.isEmpty {
                                    Text("Missing Headers: \(tlsResult.missingSecurityHeaders.joined(separator: ", "))")
                                        .font(.caption)
                                        .foregroundStyle(.orange)
                                }
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
            }
            .padding()
        }
    }
}

struct LANDevicesView: View {
    @ObservedObject var wifiService: WiFiService
    @State private var devices: [LANDevice] = []
    @State private var exportStatus: String?
    private let lanService = LANDiscoveryService()
    private let auditService = SecurityAuditService()
    private let channelAnalyzer = ChannelAnalyzer()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("LAN Devices & Audit Report")
                        .font(.title2.bold())
                    Text("Inspects active ARP table neighbors on your subnet and exports a Markdown audit report.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    devices = lanService.discoverARPDevices()
                } label: {
                    Label("Refresh LAN", systemImage: "arrow.clockwise")
                }
                Button {
                    exportReport()
                } label: {
                    Label("Export Report", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.borderedProminent)
            }

            if let exportStatus {
                Text(exportStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if devices.isEmpty {
                ContentUnavailableView(
                    "No LAN Devices Found",
                    systemImage: "desktopcomputer",
                    description: Text("Click Refresh LAN to read active ARP neighbors.")
                )
            } else {
                Table(devices) {
                    TableColumn("IP Address") { d in Text(d.ip).monospaced() }
                    TableColumn("Hostname") { d in Text(d.hostname) }
                    TableColumn("MAC Address") { d in Text(d.mac).monospaced() }
                    TableColumn("Interface") { d in Text(d.interfaceName) }
                }
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear {
            devices = lanService.discoverARPDevices()
        }
    }

    private func exportReport() {
        let findings = auditService.audit(
            current: wifiService.currentNetwork,
            nearby: wifiService.scannedNetworks
        )
        let channels = channelAnalyzer.analyze(networks: wifiService.scannedNetworks)
        let markdown = AuditReportExporter.generateMarkdown(
            currentNetwork: wifiService.currentNetwork,
            findings: findings,
            channelRecommendations: channels.recommendations,
            lanDevices: devices,
            dnsSecurity: nil,
            portResults: []
        )

        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "WiFiDoctor-Audit-Report.md"
        if panel.runModal() == .OK, let url = panel.url {
            do {
                try markdown.write(to: url, atomically: true, encoding: .utf8)
                exportStatus = "Saved report to \(url.path)"
            } catch {
                exportStatus = "Failed to save report: \(error.localizedDescription)"
            }
        }
    }
}
