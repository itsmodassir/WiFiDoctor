import SwiftUI
import WiFiDoctorCore

enum SidebarTab: String, CaseIterable, Identifiable {
    case wifi = "Wi-Fi & Connect"
    case signal = "Live Signal Monitor"
    case audit = "Security Audit"
    case channels = "Channel Analyzer"
    case diagnostics = "Connectivity & Latency"
    case jitter = "Jitter & Packet Loss"
    case bufferbloat = "Bufferbloat & Speed"
    case traceroute = "Traceroute & DHCP"
    case ports = "Port & Host Check"
    case dnsTls = "DNS & TLS Inspector"
    case bonjour = "Bonjour Services"
    case lan = "LAN Devices & Report"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .wifi: return "wifi"
        case .signal: return "waveform.path"
        case .audit: return "shield.lefthalf.filled"
        case .channels: return "antenna.radiowaves.left.and.right"
        case .diagnostics: return "waveform.path.ecg"
        case .jitter: return "chart.xyaxis.line"
        case .bufferbloat: return "speedometer"
        case .traceroute: return "point.topleft.down.curvedto.point.bottomright.up"
        case .ports: return "network"
        case .dnsTls: return "lock.shield"
        case .bonjour: return "bonjour"
        case .lan: return "desktopcomputer"
        }
    }
}

@main
struct WiFiDoctorApp: App {
    @StateObject private var wifiService = WiFiService()
    @State private var selectedTab: SidebarTab? = .wifi

    var body: some Scene {
        WindowGroup {
            NavigationSplitView {
                List(SidebarTab.allCases, id: \.self, selection: $selectedTab) { tab in
                    Label(tab.rawValue, systemImage: tab.icon)
                        .tag(tab)
                }
                .navigationTitle("WiFiDoctor")
                .listStyle(.sidebar)
                .navigationSplitViewColumnWidth(min: 200, ideal: 220)
            } detail: {
                let activeTab = selectedTab ?? .wifi
                detailView(for: activeTab)
                    .id(activeTab)
                    .frame(minWidth: 640, maxWidth: .infinity, minHeight: 460, maxHeight: .infinity, alignment: .topLeading)
            }
            .frame(minWidth: 860, minHeight: 540)
        }
    }

    @ViewBuilder
    private func detailView(for tab: SidebarTab) -> some View {
        switch tab {
        case .wifi:
            WiFiListView(wifiService: wifiService)
        case .signal:
            SignalMonitorView(wifiService: wifiService)
        case .audit:
            SecurityAuditView(wifiService: wifiService)
        case .channels:
            ChannelAnalyzerView(wifiService: wifiService)
        case .diagnostics:
            DiagnosticsView(wifiService: wifiService)
        case .jitter:
            JitterMonitorView()
        case .bufferbloat:
            BufferbloatView()
        case .traceroute:
            TracerouteAndDHCPView(wifiService: wifiService)
        case .ports:
            PortCheckView()
        case .dnsTls:
            DNSTLSInspectorView()
        case .bonjour:
            BonjourBrowserView()
        case .lan:
            LANDevicesView(wifiService: wifiService)
        }
    }
}
