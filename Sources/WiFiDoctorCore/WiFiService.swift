import CoreLocation
@preconcurrency import CoreWLAN
import Foundation

private struct UncheckedSendableBox<T>: @unchecked Sendable {
    let value: T
}

/// Manages Wi-Fi interface inspection, scanning, Location permission, and connecting to networks.
@MainActor
public final class WiFiService: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published public private(set) var currentNetwork: WiFiNetworkInfo?
    @Published public private(set) var scannedNetworks: [WiFiNetworkInfo] = []
    @Published public private(set) var interfaceName: String?
    @Published public private(set) var isScanning: Bool = false
    @Published public private(set) var isConnecting: Bool = false
    @Published public private(set) var locationStatus: CLAuthorizationStatus = .notDetermined
    @Published public private(set) var lastError: String?

    private let client = CWWiFiClient.shared()
    private let locationManager = CLLocationManager()
    private var scannedCache: [String: CWNetwork] = [:]

    public override init() {
        super.init()
        locationManager.delegate = self
        locationStatus = locationManager.authorizationStatus
        refreshCurrentConnection()
    }

    public func requestLocationPermission() {
        locationManager.requestWhenInUseAuthorization()
    }

    nonisolated public func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        Task { @MainActor in
            self.locationStatus = status
            self.refreshCurrentConnection()
        }
    }

    /// Reads the active Wi-Fi interface state.
    public func refreshCurrentConnection() {
        guard let interface = client.interface() else {
            interfaceName = nil
            currentNetwork = nil
            lastError = "No Wi-Fi hardware interface found."
            return
        }

        interfaceName = interface.interfaceName
        guard interface.powerOn() else {
            currentNetwork = nil
            lastError = "Wi-Fi is turned off."
            return
        }

        let ssid = interface.ssid()
        let bssid = interface.bssid()
        let channelObj = interface.wlanChannel()
        let channel = channelObj?.channelNumber ?? 0
        let band = Self.bandLabel(for: channelObj?.channelBand)
        let security = Self.mapSecurity(interface.security())

        if ssid != nil || bssid != nil || channel > 0 {
            currentNetwork = WiFiNetworkInfo(
                ssid: ssid,
                bssid: bssid,
                rssi: interface.rssiValue(),
                noise: interface.noiseMeasurement(),
                channel: channel,
                band: band,
                security: security,
                transmitRateMbps: interface.transmitRate(),
                isCurrent: true
            )
            lastError = nil
        } else {
            currentNetwork = nil
        }
    }

    /// Scans for nearby Wi-Fi networks using CoreWLAN.
    public func scanNetworks() async {
        guard let interface = client.interface() else {
            lastError = "No Wi-Fi interface available."
            return
        }
        guard interface.powerOn() else {
            lastError = "Turn on Wi-Fi to scan for networks."
            return
        }

        isScanning = true
        lastError = nil
        defer { isScanning = false }

        do {
            let interfaceBox = UncheckedSendableBox(value: interface)
            let networksBox = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UncheckedSendableBox<Set<CWNetwork>>, Error>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        let found = try interfaceBox.value.scanForNetworks(withName: nil)
                        continuation.resume(returning: UncheckedSendableBox(value: found))
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
            let networks = networksBox.value

            let activeBSSID = interface.bssid()
            var cache: [String: CWNetwork] = [:]
            var mapped: [WiFiNetworkInfo] = []

            for net in networks {
                let channelObj = net.wlanChannel
                let channel = channelObj?.channelNumber ?? 0
                let band = Self.bandLabel(for: channelObj?.channelBand)
                let security = Self.mapCWNetworkSecurity(net)
                let isCurrent = (activeBSSID != nil && net.bssid == activeBSSID)
                let info = WiFiNetworkInfo(
                    ssid: net.ssid,
                    bssid: net.bssid,
                    rssi: net.rssiValue,
                    noise: net.noiseMeasurement,
                    channel: channel,
                    band: band,
                    security: security,
                    transmitRateMbps: nil,
                    isCurrent: isCurrent
                )
                cache[info.id] = net
                mapped.append(info)
            }

            scannedCache = cache
            scannedNetworks = mapped.sorted { $0.rssi > $1.rssi }
            refreshCurrentConnection()
        } catch {
            lastError = "Wi-Fi scan failed: \(error.localizedDescription)"
        }
    }

    /// Connects to a scanned Wi-Fi network using a known password (or nil for open networks).
    public func connect(to networkInfo: WiFiNetworkInfo, password: String?) async throws {
        guard let interface = client.interface() else {
            throw NSError(domain: "WiFiDoctor", code: 1, userInfo: [NSLocalizedDescriptionKey: "No Wi-Fi interface available."])
        }
        guard let target = scannedCache[networkInfo.id] else {
            throw NSError(domain: "WiFiDoctor", code: 2, userInfo: [NSLocalizedDescriptionKey: "Network is no longer in the scan cache. Please rescan."])
        }

        isConnecting = true
        lastError = nil
        defer { isConnecting = false }

        let trimmedPassword = (password?.isEmpty == true) ? nil : password
        let interfaceBox = UncheckedSendableBox(value: interface)
        let targetBox = UncheckedSendableBox(value: target)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try interfaceBox.value.associate(to: targetBox.value, password: trimmedPassword)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }

        refreshCurrentConnection()
    }

    private static func bandLabel(for band: CWChannelBand?) -> String {
        switch band {
        case .band2GHz: return "2.4 GHz"
        case .band5GHz: return "5 GHz"
        case .band6GHz: return "6 GHz"
        default: return "Unknown"
        }
    }

    private static func mapSecurity(_ security: CWSecurity) -> WiFiSecurityLevel {
        switch security {
        case .none:
            return .open
        case .WEP, .dynamicWEP:
            return .wep
        case .wpaPersonal, .wpaPersonalMixed:
            return .wpaPersonal
        case .wpa2Personal, .personal:
            return .wpa2Personal
        case .wpa3Personal, .wpa3Transition:
            return .wpa3Personal
        case .wpaEnterprise, .wpaEnterpriseMixed, .wpa2Enterprise, .enterprise, .wpa3Enterprise:
            return .wpaEnterprise
        default:
            return .unknown
        }
    }

    private static func mapCWNetworkSecurity(_ net: CWNetwork) -> WiFiSecurityLevel {
        if net.supportsSecurity(.wpa3Personal) || net.supportsSecurity(.wpa3Transition) {
            return .wpa3Personal
        }
        if net.supportsSecurity(.wpa3Enterprise) || net.supportsSecurity(.wpa2Enterprise) || net.supportsSecurity(.wpaEnterprise) || net.supportsSecurity(.enterprise) {
            return .wpaEnterprise
        }
        if net.supportsSecurity(.wpa2Personal) || net.supportsSecurity(.personal) {
            return .wpa2Personal
        }
        if net.supportsSecurity(.wpaPersonal) || net.supportsSecurity(.wpaPersonalMixed) {
            return .wpaPersonal
        }
        if net.supportsSecurity(.WEP) || net.supportsSecurity(.dynamicWEP) {
            return .wep
        }
        if net.supportsSecurity(.none) {
            return .open
        }
        return .unknown
    }
}
