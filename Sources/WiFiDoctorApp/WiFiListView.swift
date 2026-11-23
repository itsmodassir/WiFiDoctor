import CoreLocation
import SwiftUI
import WiFiDoctorCore

struct WiFiListView: View {
    @ObservedObject var wifiService: WiFiService
    @State private var networkToConnect: WiFiNetworkInfo?
    @State private var passwordInput: String = ""
    @State private var connectStatusMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            headerBar

            if wifiService.locationStatus != .authorizedAlways {
                locationBanner
            }

            if let error = wifiService.lastError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.callout)
            }

            if let connectStatusMessage {
                Label(connectStatusMessage, systemImage: "info.circle")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }

            activeConnectionCard

            Text("Nearby Wi-Fi Networks (\(wifiService.scannedNetworks.count))")
                .font(.headline)

            Table(wifiService.scannedNetworks) {
                TableColumn("SSID") { net in
                    HStack(spacing: 6) {
                        if net.isCurrent {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        }
                        Text(net.displayName)
                            .fontWeight(net.isCurrent ? .semibold : .regular)
                    }
                }
                TableColumn("Security") { net in
                    Text(net.security.rawValue)
                        .foregroundStyle(net.security.isWeak ? .red : .primary)
                }
                TableColumn("Channel") { net in
                    Text("\(net.channel) (\(net.band))")
                }
                TableColumn("RSSI / SNR") { net in
                    Text("\(net.rssi) dBm / \(net.snr) dB")
                        .monospacedDigit()
                }
                TableColumn("Action") { net in
                    Button(net.isCurrent ? "Connected" : "Connect") {
                        passwordInput = ""
                        networkToConnect = net
                    }
                    .disabled(net.isCurrent || wifiService.isConnecting)
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task {
            if wifiService.scannedNetworks.isEmpty {
                await wifiService.scanNetworks()
            }
        }
        .sheet(item: $networkToConnect) { net in
            connectSheet(for: net)
        }
    }

    private var headerBar: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Wi-Fi Scanner & Connection")
                    .font(.title2.bold())
                Text("Interface: \(wifiService.interfaceName ?? "Unavailable")")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                wifiService.refreshCurrentConnection()
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            Button {
                Task { await wifiService.scanNetworks() }
            } label: {
                if wifiService.isScanning {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Scan Networks", systemImage: "dot.radiowaves.left.and.right")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(wifiService.isScanning)
        }
    }

    private var locationBanner: some View {
        HStack {
            Image(systemName: "location.slash.fill")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Location Access Needed for SSID/BSSID")
                    .font(.subheadline.bold())
                Text("macOS redacts Wi-Fi names until Location permission is granted.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Grant Permission") {
                wifiService.requestLocationPermission()
            }
            .buttonStyle(.bordered)
        }
        .padding(10)
        .background(.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }

    private var activeConnectionCard: some View {
        GroupBox("Active Connection") {
            if let current = wifiService.currentNetwork {
                Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 6) {
                    GridRow {
                        Text("SSID:").foregroundStyle(.secondary)
                        Text(current.displayName).bold()
                        Text("Security:").foregroundStyle(.secondary)
                        Text(current.security.rawValue)
                            .foregroundStyle(current.security.isWeak ? .red : .green)
                    }
                    GridRow {
                        Text("BSSID:").foregroundStyle(.secondary)
                        Text(current.bssid ?? "Redacted").monospaced()
                        Text("Channel:").foregroundStyle(.secondary)
                        Text("\(current.channel) (\(current.band))")
                    }
                    GridRow {
                        Text("Signal / Noise:").foregroundStyle(.secondary)
                        Text("\(current.rssi) dBm / \(current.noise) dBm (SNR \(current.snr) dB)")
                            .monospacedDigit()
                        Text("Tx Rate:").foregroundStyle(.secondary)
                        Text(current.transmitRateMbps.map { String(format: "%.0f Mbps", $0) } ?? "—")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            } else {
                Text("Not connected to a Wi-Fi network.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
            }
        }
    }

    private func connectSheet(for network: WiFiNetworkInfo) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Connect to \(network.displayName)")
                .font(.headline)
            Text("Security: \(network.security.rawValue) • Channel \(network.channel) (\(network.band))")
                .font(.caption)
                .foregroundStyle(.secondary)

            if network.security != .open {
                SecureField("Wi-Fi Password", text: $passwordInput)
                    .textFieldStyle(.roundedBorder)
            } else {
                Text("This is an open network (no password required).")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }

            HStack {
                Spacer()
                Button("Cancel") {
                    networkToConnect = nil
                }
                Button("Connect") {
                    let target = network
                    let pwd = passwordInput
                    networkToConnect = nil
                    Task {
                        do {
                            try await wifiService.connect(to: target, password: pwd)
                            connectStatusMessage = "Connected to \(target.displayName)."
                        } catch {
                            connectStatusMessage = "Failed to connect to \(target.displayName): \(error.localizedDescription)"
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .frame(width: 360)
    }
}
