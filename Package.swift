// swift-tools-version:5.9
//
// Test-only Swift package: it compiles the React-free part of the iOS sources so that
// they can be unit-tested with XCTest on an iOS simulator:
//
//   xcodebuild test -scheme RootJailDetectCore -destination 'platform=iOS Simulator,name=iPhone 17'
//
// The library itself is still distributed through CocoaPods (RootJailDetect.podspec).
import PackageDescription

let package = Package(
  name: "RootJailDetectCore",
  platforms: [.iOS(.v15)],
  products: [
    .library(name: "RootJailDetectCore", targets: ["RootJailDetectCore"])
  ],
  targets: [
    .target(
      name: "RootJailDetectCore",
      path: "ios",
      exclude: ["RootJailDetect.swift", "RootJailDetect.m"],
      sources: [
        "Checkers", "Constants", "Protocol", "Utils", "Watchdog", "JailbreakDetection.swift",
      ]
    ),
    .testTarget(
      name: "RootJailDetectCoreTests",
      dependencies: ["RootJailDetectCore"],
      path: "Tests/RootJailDetectCoreTests"
    ),
  ]
)
