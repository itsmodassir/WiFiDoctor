import Charts
import SwiftUI
import WiFiDoctorCore

struct BufferbloatView: View {
    @State private var pingHost = "1.1.1.1"
    @State private var result: BufferbloatResult?
    @State private var isRunning = false
    private let service = BufferbloatService()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Bufferbloat & Throughput-Under-Load")
                        .font(.title2.bold())
                    Text("Measures baseline ping vs. latency during a 10 MB download to detect router queueing lag.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task {
                        isRunning = true
                        result = await service.runTest(pingHost: pingHost)
                        isRunning = false
                    }
                } label: {
                    if isRunning {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Run Bufferbloat Test", systemImage: "speedometer")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isRunning || pingHost.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            HStack {
                LabeledContent("Ping Target") {
                    TextField("1.1.1.1", text: $pingHost)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 160)
                }
            }

            if let result {
                HStack(spacing: 16) {
                    metricCard("Bufferbloat Grade", result.grade, color: gradeColor(result.grade))
                    metricCard("Download Speed", String(format: "%.1f Mbps", result.downloadMbps), color: .blue)
                    metricCard("Baseline Ping", String(format: "%.1f ms", result.baselineAvgMs), color: .primary)
                    metricCard("Loaded Ping", String(format: "%.1f ms", result.loadedAvgMs), color: result.deltaMs > 50 ? .orange : .green)
                    metricCard("Latency Spike", String(format: "+%.1f ms", result.deltaMs), color: result.deltaMs > 50 ? .orange : .green)
                }

                if let err = result.errorMessage {
                    Label(err, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            } else {
                ContentUnavailableView(
                    "Ready to Test",
                    systemImage: "speedometer",
                    description: Text("Click Run Bufferbloat Test to check download speed and latency under load.")
                )
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func metricCard(_ title: String, _ value: String, color: Color) -> some View {
        GroupBox(title) {
            Text(value)
                .font(.title3.bold())
                .foregroundStyle(color)
                .monospacedDigit()
                .frame(minWidth: 100, alignment: .leading)
                .padding(4)
        }
    }

    private func gradeColor(_ grade: String) -> Color {
        switch grade {
        case "A+", "A": return .green
        case "B": return .blue
        case "C": return .orange
        default: return .red
        }
    }
}

struct JitterSample: Identifiable {
    let id = UUID()
    let index: Int
    let rttMs: Double?
}

struct JitterMonitorView: View {
    @State private var targetHost = DiagnosticsService.detectDefaultGateway() ?? "1.1.1.1"
    @State private var samples: [JitterSample] = []
    @State private var isRunning = false
    @State private var lastStatusText: String = "Ready"
    @State private var monitorTask: Task<Void, Never>?

    private var validRTTs: [Double] {
        samples.compactMap(\.rttMs)
    }

    private var packetLossPercent: Double {
        guard !samples.isEmpty else { return 0 }
        let lost = samples.filter { $0.rttMs == nil }.count
        return (Double(lost) / Double(samples.count)) * 100.0
    }

    private var avgRTT: Double {
        guard !validRTTs.isEmpty else { return 0 }
        return validRTTs.reduce(0, +) / Double(validRTTs.count)
    }

    private var jitterMs: Double {
        JitterCalculator.computeJitter(rtts: validRTTs)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Continuous Jitter & Packet-Loss Monitor")
                        .font(.title2.bold())
                    Text("Pings every second to catch intermittent Wi-Fi latency spikes and packet drops.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Clear") { samples.removeAll() }
                Button {
                    if isRunning { stopMonitor() } else { startMonitor() }
                } label: {
                    Label(isRunning ? "Stop" : "Start Monitor", systemImage: isRunning ? "stop.fill" : "play.fill")
                }
                .buttonStyle(.borderedProminent)
            }

            HStack(spacing: 12) {
                TextField("Target host or gateway IP", text: $targetHost)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
                Button("Use Gateway") {
                    if let gw = DiagnosticsService.detectDefaultGateway() {
                        targetHost = gw
                    }
                }
                Button("Use 1.1.1.1") {
                    targetHost = "1.1.1.1"
                }
            }

            HStack(spacing: 16) {
                statBox("Samples", "\(samples.count)", color: .primary)
                statBox("Avg RTT", String(format: "%.1f ms", avgRTT), color: .blue)
                statBox("Jitter", String(format: "%.2f ms", jitterMs), color: jitterMs > 15 ? .orange : .green)
                statBox("Packet Loss", String(format: "%.1f%%", packetLossPercent), color: packetLossPercent > 0 ? .red : .green)
            }

            Text("Status: \(lastStatusText)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()

            if validRTTs.count >= 2 {
                GroupBox("RTT Timeline (ms)") {
                    Chart(samples) { s in
                        if let rtt = s.rttMs {
                            LineMark(
                                x: .value("Sample", s.index),
                                y: .value("RTT (ms)", rtt)
                            )
                            .foregroundStyle(.blue)
                            PointMark(
                                x: .value("Sample", s.index),
                                y: .value("RTT (ms)", rtt)
                            )
                            .foregroundStyle(rtt > 100 ? .orange : .blue)
                        }
                    }
                    .frame(height: 220)
                    .padding(6)
                }
            } else {
                ContentUnavailableView(
                    isRunning ? "Collecting Samples..." : "Monitor Stopped",
                    systemImage: "waveform.path.ecg",
                    description: Text(isRunning ? "Waiting for at least 2 ping replies to plot the timeline." : "Click Start Monitor to track live jitter and packet loss.")
                )
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onDisappear { stopMonitor() }
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

    private func startMonitor() {
        stopMonitor()
        let host = targetHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else {
            lastStatusText = "Enter a valid host or IP."
            return
        }
        isRunning = true
        lastStatusText = "Pinging \(host)..."
        monitorTask = Task {
            var counter = (samples.last?.index ?? 0)
            while !Task.isCancelled {
                counter += 1
                let ping = await DiagnosticsService.ping(host: host, count: 1)
                samples.append(JitterSample(index: counter, rttMs: ping.avgMs))
                if let rtt = ping.avgMs {
                    lastStatusText = String(format: "Sample #%d → %@: %.2f ms", counter, host, rtt)
                } else {
                    lastStatusText = "Sample #\(counter) → \(host): \(ping.errorMessage ?? "Packet Lost / Timeout")"
                }
                if samples.count > 120 {
                    samples.removeFirst(samples.count - 120)
                }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func stopMonitor() {
        monitorTask?.cancel()
        monitorTask = nil
        isRunning = false
        if samples.isEmpty {
            lastStatusText = "Ready"
        }
    }
}

struct BonjourBrowserView: View {
    @StateObject private var browser = BonjourBrowserService()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("mDNS / Bonjour Service Browser")
                        .font(.title2.bold())
                    Text("Discovers advertised HTTP, SSH, SMB, AFP, and printer services on your local Wi-Fi.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    if browser.isBrowsing {
                        browser.stopBrowsing()
                    } else {
                        browser.startBrowsing()
                    }
                } label: {
                    Label(browser.isBrowsing ? "Stop Browsing" : "Browse Services", systemImage: "bonjour")
                }
                .buttonStyle(.borderedProminent)
            }

            if browser.items.isEmpty {
                ContentUnavailableView(
                    browser.isBrowsing ? "Listening for Bonjour Services..." : "No Services Listed",
                    systemImage: "bonjour",
                    description: Text("Click Browse Services to discover mDNS advertisements on your LAN.")
                )
            } else {
                Table(browser.items) {
                    TableColumn("Service Name") { item in Text(item.name).bold() }
                    TableColumn("Type") { item in Text(item.serviceType).monospaced() }
                    TableColumn("Domain") { item in Text(item.domain) }
                }
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear {
            if !browser.isBrowsing && browser.items.isEmpty {
                browser.startBrowsing()
            }
        }
        .onDisappear {
            browser.stopBrowsing()
        }
    }
}
