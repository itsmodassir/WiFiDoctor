# WiFiDoctor

A native macOS SwiftUI network diagnostics, Wi-Fi engineering, and defensive security auditing app.

## Features

- **Wi-Fi & Connect**: Inspect active Wi-Fi interface metrics (SSID, BSSID, RSSI, Noise, SNR, Channel/Band, Tx Rate, Security), scan nearby networks via `CoreWLAN`, and connect with known credentials.
- **Live Signal Monitor**: Real-time 1.5s polling of RSSI, Noise, SNR, and Tx Rate with a SwiftUI `Charts` timeline for coverage walk-testing.
- **Security Audit & Passphrase Policy**: Flags weak/legacy encryption (Open, WEP, WPA/TKIP), duplicate SSIDs with mismatched security modes, and low SNR; includes an offline Wi-Fi passphrase entropy & policy checker.
- **Channel Analyzer**: Analyzes nearby AP congestion across 2.4 GHz and 5 GHz bands and recommends the cleanest channels.
- **Connectivity & Latency**: Detects local IPv4, default gateway, DNS servers, ICMP ping RTT/packet loss, DNS resolution timing, and captive portals.
- **Jitter & Packet Loss**: Continuous 1-second ping monitor with live RTT chart, jitter calculation, and packet-loss percentage.
- **Bufferbloat & Speed**: Measures baseline ping vs. loaded ping during a download to report throughput (Mbps) and a Bufferbloat grade (`A+` to `D`).
- **Traceroute & DHCP**: Displays interface MAC, MTU, IPv4, subnet mask, DHCP server, lease duration, and hop-by-hop traceroute latency.
- **Port & Host Check**: Asynchronous TCP port reachability scanner (`Network.framework`) with Router & IoT audit presets and hardening notes.
- **DNS & TLS Inspector**: Compares local DNS against Cloudflare DoH (`1.1.1.1`) and inspects HTTPS certificates and HTTP security headers.
- **Bonjour Services**: Live mDNS/Bonjour service browser (`NWBrowser`).
- **LAN Devices & Report**: Reads active ARP neighbors and exports a Markdown audit report.

## Requirements

- macOS 14.0+
- Xcode 16+ / Swift 6.0+
- Location permission (prompted on launch) so macOS exposes unredacted Wi-Fi SSIDs and BSSIDs.

## Build & Run

```bash
# Run unit tests
swift test

# Build and package WiFiDoctor.app
./scripts/build_app.sh

# Launch the app
open build/WiFiDoctor.app
```

## License

MIT License — see [LICENSE](LICENSE).
