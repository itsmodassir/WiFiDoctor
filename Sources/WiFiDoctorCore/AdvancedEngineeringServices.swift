import Foundation
import Network

// MARK: - Bufferbloat & Throughput-Under-Load Test

public struct BufferbloatResult: Sendable, Equatable {
    public let baselineAvgMs: Double
    public let loadedAvgMs: Double
    public let deltaMs: Double
    public let downloadMbps: Double
    public let grade: String
    public let errorMessage: String?
}

public struct BufferbloatService: Sendable {
    public init() {}

    public static func grade(baselineMs: Double, loadedMs: Double) -> (deltaMs: Double, grade: String) {
        let delta = max(0, loadedMs - baselineMs)
        let letter: String
        switch delta {
        case ..<5: letter = "A+"
        case ..<30: letter = "A"
        case ..<60: letter = "B"
        case ..<200: letter = "C"
        default: letter = "D"
        }
        return (delta, letter)
    }

    public func runTest(
        pingHost: String = "1.1.1.1",
        downloadURLString: String = "https://speed.cloudflare.com/__down?bytes=10000000"
    ) async -> BufferbloatResult {
        let baseline = await DiagnosticsService.ping(host: pingHost, count: 4)
        guard let baseAvg = baseline.avgMs else {
            return BufferbloatResult(
                baselineAvgMs: 0,
                loadedAvgMs: 0,
                deltaMs: 0,
                downloadMbps: 0,
                grade: "N/A",
                errorMessage: baseline.errorMessage ?? "Baseline ping failed."
            )
        }

        guard let url = URL(string: downloadURLString) else {
            return BufferbloatResult(
                baselineAvgMs: baseAvg,
                loadedAvgMs: baseAvg,
                deltaMs: 0,
                downloadMbps: 0,
                grade: "N/A",
                errorMessage: "Invalid download test URL."
            )
        }

        let start = DispatchTime.now().uptimeNanoseconds
        async let downloadTask: (Int, Error?) = {
            do {
                var req = URLRequest(url: url)
                req.timeoutInterval = 15.0
                req.cachePolicy = .reloadIgnoringLocalCacheData
                let (data, _) = try await URLSession.shared.data(for: req)
                return (data.count, nil)
            } catch {
                return (0, error)
            }
        }()

        async let loadedPingTask = DiagnosticsService.ping(host: pingHost, count: 4)

        let ((bytesCount, dlError), loadedPing) = await (downloadTask, loadedPingTask)
        let elapsedSec = max(0.001, Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000.0)
        let mbps = (Double(bytesCount) * 8.0) / (elapsedSec * 1_000_000.0)

        let loadedAvg = loadedPing.avgMs ?? baseAvg
        let graded = Self.grade(baselineMs: baseAvg, loadedMs: loadedAvg)

        return BufferbloatResult(
            baselineAvgMs: baseAvg,
            loadedAvgMs: loadedAvg,
            deltaMs: graded.deltaMs,
            downloadMbps: mbps,
            grade: graded.grade,
            errorMessage: dlError?.localizedDescription
        )
    }
}

// MARK: - Jitter & Packet Loss Calculator

public enum JitterCalculator {
    /// Computes average consecutive RTT variation (RFC-style mean absolute jitter).
    public static func computeJitter(rtts: [Double]) -> Double {
        guard rtts.count >= 2 else { return 0 }
        var totalDiff = 0.0
        for i in 1..<rtts.count {
            totalDiff += abs(rtts[i] - rtts[i - 1])
        }
        return totalDiff / Double(rtts.count - 1)
    }
}

// MARK: - mDNS / Bonjour Service Browser

public struct BonjourServiceItem: Identifiable, Hashable, Sendable {
    public var id: String { "\(serviceType)-\(name)-\(domain)" }
    public let name: String
    public let serviceType: String
    public let domain: String
}

@MainActor
public final class BonjourBrowserService: ObservableObject {
    @Published public private(set) var items: [BonjourServiceItem] = []
    @Published public private(set) var isBrowsing: Bool = false

    private var browsers: [NWBrowser] = []

    public static let defaultTypes: [String] = [
        "_http._tcp",
        "_https._tcp",
        "_ssh._tcp",
        "_smb._tcp",
        "_afpovertcp._tcp",
        "_printer._tcp",
        "_ipp._tcp"
    ]

    public init() {}

    public func startBrowsing(types: [String] = BonjourBrowserService.defaultTypes) {
        stopBrowsing()
        items = []
        isBrowsing = true

        for type in types {
            let params = NWParameters()
            params.includePeerToPeer = true
            let browser = NWBrowser(for: .bonjour(type: type, domain: nil), using: params)
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                let mapped: [BonjourServiceItem] = results.compactMap { result in
                    if case let .service(name, svcType, domain, _) = result.endpoint {
                        return BonjourServiceItem(name: name, serviceType: svcType, domain: domain)
                    }
                    return nil
                }
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    for entry in mapped {
                        if !self.items.contains(entry) {
                            self.items.append(entry)
                        }
                    }
                    self.items.sort {
                        if $0.serviceType != $1.serviceType { return $0.serviceType < $1.serviceType }
                        return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
                    }
                }
            }
            browser.start(queue: DispatchQueue(label: "wifidoctor.bonjour.\(type)"))
            browsers.append(browser)
        }
    }

    public func stopBrowsing() {
        for b in browsers {
            b.cancel()
        }
        browsers.removeAll()
        isBrowsing = false
    }
}
