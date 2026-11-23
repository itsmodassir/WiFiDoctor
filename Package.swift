// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WiFiDoctor",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "WiFiDoctorCore",
            targets: ["WiFiDoctorCore"]
        ),
        .executable(
            name: "WiFiDoctor",
            targets: ["WiFiDoctorApp"]
        )
    ],
    targets: [
        .target(
            name: "WiFiDoctorCore",
            linkerSettings: [
                .linkedFramework("CoreWLAN"),
                .linkedFramework("CoreLocation"),
                .linkedFramework("Network"),
                .linkedFramework("SystemConfiguration")
            ]
        ),
        .executableTarget(
            name: "WiFiDoctorApp",
            dependencies: ["WiFiDoctorCore"]
        ),
        .testTarget(
            name: "WiFiDoctorCoreTests",
            dependencies: ["WiFiDoctorCore"]
        )
    ]
)
