import XCTest
@testable import WiFiDoctorCore

final class WiFiDoctorCoreTests: XCTestCase {
    func testSecurityAuditFlagsOpenAndWEPAsCritical() {
        let audit = SecurityAuditService()
        let openNet = WiFiNetworkInfo(
            ssid: "GuestOpen",
            bssid: "aa:bb:cc:dd:ee:01",
            rssi: -50,
            noise: -90,
            channel: 6,
            band: "2.4 GHz",
            security: .open,
            isCurrent: true
        )

        let findings = audit.audit(current: openNet, nearby: [openNet])
        XCTAssertTrue(findings.contains { $0.severity == .critical && $0.title.contains("Open Wi-Fi") })
        XCTAssertTrue(findings.contains { $0.severity == .pass && $0.title.contains("Healthy Signal-to-Noise") })
    }

    func testSecurityAuditDetectsDuplicateSSIDWithMismatchedSecurity() {
        let audit = SecurityAuditService()
        let corpSecure = WiFiNetworkInfo(
            ssid: "CorpNet",
            bssid: "aa:bb:cc:dd:ee:01",
            rssi: -55,
            noise: -90,
            channel: 36,
            band: "5 GHz",
            security: .wpa3Personal,
            isCurrent: true
        )
        let corpOpen = WiFiNetworkInfo(
            ssid: "CorpNet",
            bssid: "aa:bb:cc:dd:ee:99",
            rssi: -60,
            noise: -90,
            channel: 1,
            band: "2.4 GHz",
            security: .open,
            isCurrent: false
        )

        let findings = audit.audit(current: corpSecure, nearby: [corpSecure, corpOpen])
        XCTAssertTrue(findings.contains { $0.severity == .critical && $0.title.contains("Mismatched Security Modes") })
    }

    func testSecurityAuditFlagsLowSNR() {
        let audit = SecurityAuditService()
        let weakSNR = WiFiNetworkInfo(
            ssid: "Office",
            bssid: "11:22:33:44:55:66",
            rssi: -82,
            noise: -92,
            channel: 149,
            band: "5 GHz",
            security: .wpa2Personal,
            isCurrent: true
        )

        let findings = audit.audit(current: weakSNR, nearby: [weakSNR])
        XCTAssertTrue(findings.contains { $0.severity == .warning && $0.title.contains("Low Signal-to-Noise") })
    }

    func testParsePingOutput() {
        let sample = """
        PING 1.1.1.1 (1.1.1.1): 56 data bytes
        64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.345 ms
        64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=14.100 ms

        --- 1.1.1.1 ping statistics ---
        2 packets transmitted, 2 packets received, 0.0% packet loss
        round-trip min/avg/max/stddev = 12.345/13.222/14.100/0.877 ms
        """

        let result = DiagnosticsService.parsePingOutput(host: "1.1.1.1", output: sample, exitCode: 0)
        XCTAssertEqual(result.transmitted, 2)
        XCTAssertEqual(result.received, 2)
        XCTAssertEqual(result.packetLossPercent, 0.0, accuracy: 0.01)
        XCTAssertEqual(result.minMs ?? 0, 12.345, accuracy: 0.001)
        XCTAssertEqual(result.avgMs ?? 0, 13.222, accuracy: 0.001)
        XCTAssertEqual(result.maxMs ?? 0, 14.100, accuracy: 0.001)
        XCTAssertNil(result.errorMessage)
    }

    func testParseGatewayAndDNS() {
        let routeOutput = """
           route to: default
        destination: default
               mask: default
            gateway: 192.168.1.1
          interface: en0
        """
        XCTAssertEqual(DiagnosticsService.parseGatewayOutput(routeOutput), "192.168.1.1")

        let scutilOutput = """
        resolver #1
          nameserver[0] : 192.168.1.1
          nameserver[1] : 1.1.1.1
        resolver #2
          nameserver[0] : 192.168.1.1
        """
        XCTAssertEqual(DiagnosticsService.parseDNSServers(scutilOutput), ["192.168.1.1", "1.1.1.1"])
    }

    func testPortListParsingAndHardeningNotes() {
        let ports = PortCheckService.parsePortList("443, 22, 80, 22, 99999, 0, abc")
        XCTAssertEqual(ports, [22, 80, 443])

        let telnetMeta = PortCheckService.serviceMetadata(for: 23)
        XCTAssertEqual(telnetMeta.name, "Telnet")
        XCTAssertNotNil(telnetMeta.insecureNote)

        let httpsMeta = PortCheckService.serviceMetadata(for: 443)
        XCTAssertEqual(httpsMeta.name, "HTTPS")
        XCTAssertNil(httpsMeta.insecureNote)

        let ranged = PortCheckService.parsePortList("20-23, 7547")
        XCTAssertEqual(ranged, [20, 21, 22, 23, 7547])
        XCTAssertNotNil(PortCheckService.serviceMetadata(for: 7547).insecureNote)
    }

    func testChannelAnalyzerRecommendsLeastCongestedChannel() {
        let nets = [
            WiFiNetworkInfo(ssid: "Net1", bssid: "01", rssi: -50, noise: -90, channel: 1, band: "2.4 GHz", security: .wpa2Personal),
            WiFiNetworkInfo(ssid: "Net2", bssid: "02", rssi: -55, noise: -90, channel: 1, band: "2.4 GHz", security: .wpa2Personal),
            WiFiNetworkInfo(ssid: "Net3", bssid: "03", rssi: -60, noise: -90, channel: 6, band: "2.4 GHz", security: .wpa2Personal)
        ]
        let result = ChannelAnalyzer().analyze(networks: nets)
        let rec24 = result.recommendations.first { $0.band == "2.4 GHz" }
        XCTAssertEqual(rec24?.recommendedChannel, 11)
    }

    func testParseARPOutputAndReportExport() {
        let sampleARP = """
        reliance.reliance (192.168.29.1) at a8:88:1f:10:5f:46 on en0 ifscope [ethernet]
        ? (192.168.29.69) at 1a:e9:c9:2f:7d:d2 on en0 ifscope permanent [ethernet]
        ? (192.168.29.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
        """
        let devices = LANDiscoveryService.parseARPOutput(sampleARP)
        XCTAssertEqual(devices.count, 2)
        XCTAssertEqual(devices[0].hostname, "reliance.reliance")
        XCTAssertEqual(devices[1].hostname, "Unknown")

        let report = AuditReportExporter.generateMarkdown(
            currentNetwork: nil,
            findings: [],
            channelRecommendations: [],
            lanDevices: devices,
            dnsSecurity: nil,
            portResults: []
        )
        XCTAssertTrue(report.contains("192.168.29.1"))
    }

    func testParseTracerouteOutput() {
        let sample = """
         1  192.168.29.1  2.145 ms
         2  *
         3  1.1.1.1  14.802 ms
        """
        let hops = TracerouteService.parseTracerouteOutput(sample)
        XCTAssertEqual(hops.count, 3)
        XCTAssertEqual(hops[0].hopNumber, 1)
        XCTAssertEqual(hops[0].address, "192.168.29.1")
        XCTAssertEqual(hops[0].rttMs ?? 0, 2.145, accuracy: 0.001)
        XCTAssertTrue(hops[1].timedOut)
        XCTAssertEqual(hops[2].address, "1.1.1.1")
    }

    func testParseInterfaceAndDHCPConfig() {
        let ifconfigSample = """
        en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
            ether a4:83:e7:11:22:33
            inet 192.168.29.105 netmask 0xffffff00 broadcast 192.168.29.255
        """
        let dhcpSample = """
        yiaddr = 192.168.29.105
        subnet_mask (ip): 255.255.255.0
        router (ip_mult): {192.168.29.1}
        server_identifier (ip): 192.168.29.1
        lease_time (uint32): 0x15180
        domain_name (string): reliance
        """
        let info = InterfaceInspectorService.parse(
            interfaceName: "en0",
            ifconfigOutput: ifconfigSample,
            dhcpPacketOutput: dhcpSample
        )
        XCTAssertEqual(info.macAddress, "a4:83:e7:11:22:33")
        XCTAssertEqual(info.mtu, 1500)
        XCTAssertEqual(info.ipv4Address, "192.168.29.105")
        XCTAssertEqual(info.subnetMask, "255.255.255.0")
        XCTAssertEqual(info.dhcpServerIP, "192.168.29.1")
        XCTAssertEqual(info.leaseTimeSeconds, 86400)
        XCTAssertEqual(info.domainName, "reliance")
    }

    func testPassphraseAuditor() {
        let auditor = PassphraseAuditor()
        XCTAssertEqual(auditor.evaluate("short").strength, .invalid)
        XCTAssertEqual(auditor.evaluate("12345678").strength, .weak)
        XCTAssertEqual(auditor.evaluate("K9#mP2!xQ7@vL4&zR8").strength, .veryStrong)
    }

    func testBufferbloatGradingAndJitterCalculation() {
        let gradeAPlus = BufferbloatService.grade(baselineMs: 12.0, loadedMs: 15.0)
        XCTAssertEqual(gradeAPlus.grade, "A+")
        XCTAssertEqual(gradeAPlus.deltaMs, 3.0, accuracy: 0.01)

        let gradeC = BufferbloatService.grade(baselineMs: 10.0, loadedMs: 120.0)
        XCTAssertEqual(gradeC.grade, "C")

        let jitter = JitterCalculator.computeJitter(rtts: [10.0, 14.0, 12.0, 20.0])
        // |14-10|=4, |12-14|=2, |20-12|=8 -> avg = 14 / 3 = 4.666...
        XCTAssertEqual(jitter, 14.0 / 3.0, accuracy: 0.001)
    }
}
