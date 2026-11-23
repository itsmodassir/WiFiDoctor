import SwiftUI
import WiFiDoctorCore

struct PortCheckView: View {
    @State private var targetHost: String = DiagnosticsService.detectDefaultGateway() ?? "192.168.1.1"
    @State private var portsInput: String = PortCheckService.defaultPorts.map(String.init).joined(separator: ", ")
    @State private var results: [PortCheckResult] = []
    @State private var isChecking = false
    private let service = PortCheckService()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Local Subnet & Port Reachability")
                        .font(.title2.bold())
                    Text("Checks common service and management ports on your gateway or a target host.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task { await runCheck() }
                } label: {
                    if isChecking {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Check Ports", systemImage: "network")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isChecking || targetHost.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            HStack(spacing: 12) {
                LabeledContent("Target Host") {
                    TextField("192.168.1.1", text: $targetHost)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 170)
                }
                Button("Use Gateway") {
                    if let gw = DiagnosticsService.detectDefaultGateway() {
                        targetHost = gw
                    }
                }
                .buttonStyle(.bordered)
                Button("Standard Ports") {
                    portsInput = PortCheckService.defaultPorts.map(String.init).joined(separator: ", ")
                }
                .buttonStyle(.bordered)
                Button("Router & IoT Audit") {
                    portsInput = PortCheckService.routerSecurityPorts.map(String.init).joined(separator: ", ")
                }
                .buttonStyle(.bordered)
            }

            LabeledContent("Ports / Ranges") {
                TextField("21, 22, 23, 53, 80, 443, 445, 548, 1900, 3389, 5900, 7547, 8080, 8443", text: $portsInput)
                    .textFieldStyle(.roundedBorder)
            }

            if results.isEmpty {
                ContentUnavailableView(
                    "No Port Check Run Yet",
                    systemImage: "network",
                    description: Text("Enter a gateway or local host IP and click Check Ports.")
                )
            } else {
                Table(results) {
                    TableColumn("Port") { item in
                        Text("\(item.port)")
                            .monospacedDigit()
                    }
                    TableColumn("Service") { item in
                        Text(item.serviceName)
                    }
                    TableColumn("Status") { item in
                        Text(item.status.rawValue)
                            .foregroundStyle(statusColor(item.status))
                            .bold()
                    }
                    TableColumn("Latency") { item in
                        Text(item.latencyMs.map { String(format: "%.1f ms", $0) } ?? "—")
                            .monospacedDigit()
                    }
                    TableColumn("Hardening Note") { item in
                        Text(item.securityNote ?? "—")
                            .foregroundStyle(item.securityNote != nil ? .orange : .secondary)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func runCheck() async {
        isChecking = true
        defer { isChecking = false }
        let ports = PortCheckService.parsePortList(portsInput)
        results = await service.checkPorts(host: targetHost.trimmingCharacters(in: .whitespaces), ports: ports)
    }

    private func statusColor(_ status: PortStatus) -> Color {
        switch status {
        case .open: return .green
        case .closed: return .secondary
        case .timedOut: return .orange
        }
    }
}
