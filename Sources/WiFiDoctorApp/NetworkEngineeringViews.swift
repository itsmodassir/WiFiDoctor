import Charts
import SwiftUI
import WiFiDoctorCore

struct SignalSample: Identifiable {
    let id = UUID()
    let timestamp: Date
    let rssi: Int
    let noise: Int
    let snr: Int
    let txRate: Double
}

struct SignalMonitorView: View {
    @ObservedObject var wifiService: WiFiService
    @State private var samples: [SignalSample] = []
    @State private var isMonitoring = true
    @State private var monitorTask: Task<Void, Never>?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Live Signal & Link Quality Monitor")
                        .font(.title2.bold())
                    Text("Polls RSSI, Noise, SNR, and Tx Rate every 1.5s for walk-testing Wi-Fi coverage.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Clear") {
                    samples.removeAll()
                }
                Button {
                    isMonitoring.toggle()
                    if isMonitoring { startPolling() } else { stopPolling() }
                } label: {
                    Label(isMonitoring ? "Pause" : "Resume", systemImage: isMonitoring ? "pause.fill" : "play.fill")
                }
                .buttonStyle(.borderedProminent)
            }

            if let latest = samples.last {
                HStack(spacing: 20) {
                    statBox("RSSI", "\(latest.rssi) dBm", color: latest.rssi > -65 ? .green : .orange)
                    statBox("Noise", "\(latest.noise) dBm", color: .secondary)
                    statBox("SNR", "\(latest.snr) dB", color: latest.snr >= 20 ? .green : .orange)
                    statBox("Tx Rate", String(format: "%.0f Mbps", latest.txRate), color: .blue)
                }
            }

            if samples.count >= 2 {
                GroupBox("RSSI & SNR Timeline") {
                    Chart(samples) { sample in
                        LineMark(
                            x: .value("Time", sample.timestamp),
                            y: .value("Value", sample.rssi),
                            series: .value("Metric", "RSSI (dBm)")
                        )
                        .foregroundStyle(by: .value("Metric", "RSSI (dBm)"))
                        LineMark(
                            x: .value("Time", sample.timestamp),
                            y: .value("Value", sample.snr),
                            series: .value("Metric", "SNR (dB)")
                        )
                        .foregroundStyle(by: .value("Metric", "SNR (dB)"))
                    }
                    .frame(height: 220)
                    .padding(6)
                }
            } else {
                ContentUnavailableView(
                    "Collecting Signal Samples...",
                    systemImage: "waveform.path",
                    description: Text("Ensure Wi-Fi is connected to plot live RSSI and SNR.")
                )
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear {
            if isMonitoring { startPolling() }
        }
        .onDisappear {
            stopPolling()
        }
    }

    private func statBox(_ title: String, _ value: String, color: Color) -> some View {
        GroupBox(title) {
            Text(value)
                .font(.title3.bold())
                .foregroundStyle(color)
                .monospacedDigit()
                .frame(minWidth: 95, alignment: .leading)
                .padding(4)
        }
    }

    private func startPolling() {
        stopPolling()
        monitorTask = Task {
            while !Task.isCancelled {
                wifiService.refreshCurrentConnection()
                if let net = wifiService.currentNetwork {
                    let item = SignalSample(
                        timestamp: Date(),
                        rssi: net.rssi,
                        noise: net.noise,
                        snr: net.snr,
                        txRate: net.transmitRateMbps ?? 0
                    )
                    samples.append(item)
                    if samples.count > 60 {
                        samples.removeFirst(samples.count - 60)
                    }
                }
                try? await Task.sleep(for: .milliseconds(1500))
            }
        }
    }

    private func stopPolling() {
        monitorTask?.cancel()
        monitorTask = nil
    }
}

struct TracerouteAndDHCPView: View {
    @ObservedObject var wifiService: WiFiService
    @State private var targetHost = "1.1.1.1"
    @State private var hops: [TracerouteHop] = []
    @State private var isTracing = false
    @State private var dhcpInfo: InterfaceConfigInfo?

    private let tracerouteService = TracerouteService()
    private let interfaceService = InterfaceInspectorService()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Traceroute & DHCP Inspector")
                        .font(.title2.bold())
                    Text("Inspects DHCP lease details, interface MTU/MAC, and hop-by-hop routing latency.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Refresh DHCP") {
                    loadDHCP()
                }
            }

            if let dhcp = dhcpInfo {
                GroupBox("Interface & DHCP Lease (\(dhcp.interfaceName))") {
                    Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 6) {
                        GridRow {
                            Text("IPv4 / Mask:").foregroundStyle(.secondary)
                            Text("\(dhcp.ipv4Address ?? "—") / \(dhcp.subnetMask ?? "—")").monospaced()
                            Text("DHCP Server:").foregroundStyle(.secondary)
                            Text(dhcp.dhcpServerIP ?? "—").monospaced()
                        }
                        GridRow {
                            Text("Router:").foregroundStyle(.secondary)
                            Text(dhcp.routerIP ?? "—").monospaced()
                            Text("MAC / MTU:").foregroundStyle(.secondary)
                            Text("\(dhcp.macAddress ?? "—") / \(dhcp.mtu.map(String.init) ?? "—")").monospaced()
                        }
                        GridRow {
                            Text("Lease Time:").foregroundStyle(.secondary)
                            Text(dhcp.leaseTimeSeconds.map { "\($0 / 3600)h (\($0)s)" } ?? "—")
                            Text("Domain:").foregroundStyle(.secondary)
                            Text(dhcp.domainName ?? "—")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
            }

            HStack {
                TextField("Target host or IP (e.g. 1.1.1.1)", text: $targetHost)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 260)
                Button {
                    Task {
                        isTracing = true
                        hops = await tracerouteService.runTraceroute(host: targetHost)
                        isTracing = false
                    }
                } label: {
                    if isTracing {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Run Traceroute", systemImage: "point.topleft.down.curvedto.point.bottomright.up")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isTracing || targetHost.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            if hops.isEmpty {
                ContentUnavailableView(
                    "No Traceroute Run Yet",
                    systemImage: "point.topleft.down.curvedto.point.bottomright.up",
                    description: Text("Click Run Traceroute to measure latency at each network hop.")
                )
            } else {
                Table(hops) {
                    TableColumn("Hop") { h in Text("\(h.hopNumber)").monospacedDigit() }
                    TableColumn("Address") { h in
                        Text(h.address)
                            .monospaced()
                            .foregroundStyle(h.timedOut ? .secondary : .primary)
                    }
                    TableColumn("RTT") { h in
                        Text(h.rttMs.map { String(format: "%.2f ms", $0) } ?? "Timeout")
                            .monospacedDigit()
                            .foregroundStyle(h.timedOut ? .orange : .primary)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { loadDHCP() }
    }

    private func loadDHCP() {
        let iface = wifiService.interfaceName ?? "en0"
        dhcpInfo = interfaceService.inspect(interfaceName: iface)
    }
}
