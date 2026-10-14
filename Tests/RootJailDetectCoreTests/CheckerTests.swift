import XCTest
@testable import RootJailDetectCore

// MARK: - SecurityConstants

final class SecurityConstantsTests: XCTestCase {
  func testListsAreNotEmpty() {
    XCTAssertFalse(SecurityConstants.jailbreakFilePaths.isEmpty)
    XCTAssertFalse(SecurityConstants.jailbreakURLSchemes.isEmpty)
    XCTAssertFalse(SecurityConstants.restrictedPaths.isEmpty)
  }

  func testPathsAreAbsolute() {
    for p in SecurityConstants.jailbreakFilePaths + SecurityConstants.restrictedPaths {
      XCTAssertTrue(p.hasPrefix("/"), p)
    }
  }

  func testSchemesAreValidURLs() {
    for s in SecurityConstants.jailbreakURLSchemes {
      XCTAssertTrue(s.hasSuffix("://"), s)
      XCTAssertNotNil(URL(string: s), s)
    }
  }

  func testNoDuplicatePaths() {
    let paths = SecurityConstants.jailbreakFilePaths
    XCTAssertEqual(paths.count, Set(paths).count)
  }

  func testNoWhitespaceInPaths() {
    for p in SecurityConstants.jailbreakFilePaths {
      XCTAssertEqual(p, p.trimmingCharacters(in: .whitespacesAndNewlines), p)
    }
  }
}

// MARK: - JailbreakChecker

final class JailbreakCheckerTests: XCTestCase {
  private func checker(
    files: Set<String> = [],
    writable: Bool = false,
    schemes: Set<String> = [],
    accessible: Set<String> = [],
    skipFileChecks: Bool = false
  ) -> JailbreakChecker {
    JailbreakChecker(
      fileExists: { files.contains($0) },
      canWriteFile: { _ in writable },
      canOpenURL: { schemes.contains($0.absoluteString) },
      pathAccessible: { accessible.contains($0) },
      skipFileChecks: skipFileChecks
    )
  }

  // positive
  func testCleanDevice() {
    let c = checker()
    XCTAssertFalse(c.isDeviceJailbroken())
    XCTAssertTrue(c.getReasons().isEmpty)
  }

  func testEveryKnownJailbreakFileIsDetected() {
    for path in SecurityConstants.jailbreakFilePaths {
      let c = checker(files: [path])
      XCTAssertTrue(c.isDeviceJailbroken(), path)
      XCTAssertEqual(c.getReasons(), ["Jailbreak related files detected"], path)
    }
  }

  func testWritableRestrictedDirectoryIsDetected() {
    let c = checker(writable: true)
    XCTAssertEqual(c.getReasons(), ["Writable restricted system directory"])
    XCTAssertTrue(c.isDeviceJailbroken())
  }

  func testEveryJailbreakSchemeIsDetected() {
    for scheme in SecurityConstants.jailbreakURLSchemes {
      let c = checker(schemes: [scheme])
      XCTAssertEqual(c.getReasons(), ["Jailbreak URL scheme detected"], scheme)
    }
  }

  func testEveryRestrictedPathIsDetected() {
    for path in SecurityConstants.restrictedPaths {
      let c = checker(accessible: [path])
      XCTAssertEqual(c.getReasons(), ["Restricted system paths accessible"], path)
    }
  }

  func testAllSignalsAreReportedTogether() {
    let c = checker(
      files: [SecurityConstants.jailbreakFilePaths[0]],
      writable: true,
      schemes: ["cydia://"],
      accessible: [SecurityConstants.restrictedPaths[0]]
    )
    XCTAssertEqual(c.getReasons().count, 4)
  }

  // negative
  func testUnrelatedFilesAreIgnored() {
    XCTAssertFalse(checker(files: ["/usr/bin/ls", "/Applications/Calculator.app"]).isDeviceJailbroken())
  }

  func testUnrelatedSchemesAreIgnored() {
    XCTAssertFalse(checker(schemes: ["https://", "mailto://"]).isDeviceJailbroken())
  }

  func testSimulatorBuildSkipsFileChecksOnly() {
    let c = checker(
      files: SecurityConstants.jailbreakFilePaths.reduce(into: Set<String>()) { $0.insert($1) },
      skipFileChecks: true
    )
    XCTAssertFalse(c.isDeviceJailbroken(), "host files must not be reported when running on a simulator")

    let other = checker(writable: true, skipFileChecks: true)
    XCTAssertTrue(other.isDeviceJailbroken(), "other signals still apply")
  }

  func testIsDeviceJailbrokenMatchesReasons() {
    let c = checker(writable: true)
    XCTAssertEqual(c.isDeviceJailbroken(), !c.getReasons().isEmpty)
  }

  // real system implementations
  func testSystemPathAccessible_existingAndMissing() {
    XCTAssertTrue(JailbreakChecker.systemPathAccessible("/usr"))
    XCTAssertFalse(JailbreakChecker.systemPathAccessible("/definitely/not/here"))
    XCTAssertFalse(JailbreakChecker.systemPathAccessible(""))
  }

  func testSystemCanWrite_writableTemp() {
    let path = NSTemporaryDirectory() + "rjd-\(UUID().uuidString).txt"
    XCTAssertTrue(JailbreakChecker.systemCanWrite(path))
    XCTAssertFalse(FileManager.default.fileExists(atPath: path), "probe file must be cleaned up")
  }

  func testSystemCanWrite_unwritableLocation() {
    XCTAssertFalse(JailbreakChecker.systemCanWrite("/nonexistent-dir/x/y.txt"))
  }

  func testDefaultChecker_onSimulator_doesNotFlagHostFiles() {
    XCTAssertTrue(JailbreakChecker.isSimulatorBuild, "tests are expected to run on the simulator")
    XCTAssertFalse(JailbreakChecker().getReasons().contains("Jailbreak related files detected"))
  }
}

// MARK: - SimulatorChecker

final class SimulatorCheckerTests: XCTestCase {
  func testRealDeviceWithoutEnvironment() {
    let c = SimulatorChecker(isSimulatorBuild: false, environment: { [:] })
    XCTAssertFalse(c.isSimulator())
    XCTAssertTrue(c.getReasons().isEmpty)
  }

  func testSimulatorBuildFlag() {
    let c = SimulatorChecker(isSimulatorBuild: true, environment: { [:] })
    XCTAssertEqual(c.getReasons(), ["Application running in simulator"])
    XCTAssertTrue(c.isSimulator())
  }

  func testEnvironmentVariable() {
    let c = SimulatorChecker(isSimulatorBuild: false, environment: { ["SIMULATOR_DEVICE_NAME": "iPhone 17"] })
    XCTAssertEqual(c.getReasons(), ["Simulator environment variable detected"])
  }

  func testBothSignals() {
    let c = SimulatorChecker(isSimulatorBuild: true, environment: { ["SIMULATOR_DEVICE_NAME": "x"] })
    XCTAssertEqual(c.getReasons().count, 2)
  }

  func testEmptyButPresentVariableStillCounts() {
    let c = SimulatorChecker(isSimulatorBuild: false, environment: { ["SIMULATOR_DEVICE_NAME": ""] })
    XCTAssertTrue(c.isSimulator())
  }

  func testUnrelatedEnvironmentIsIgnored() {
    let c = SimulatorChecker(isSimulatorBuild: false, environment: { ["HOME": "/", "PATH": "/bin"] })
    XCTAssertFalse(c.isSimulator())
  }

  func testDefaultCheckerRunningInSimulator() {
    XCTAssertTrue(SimulatorChecker().isSimulator())
  }
}

// MARK: - DebuggerChecker

final class DebuggerCheckerTests: XCTestCase {
  func testNotTraced() {
    let c = DebuggerChecker(skipInDebugBuild: false, isTraced: { false })
    XCTAssertFalse(c.isDebuggerAttached())
    XCTAssertTrue(c.getReasons().isEmpty)
  }

  func testTraced() {
    let c = DebuggerChecker(skipInDebugBuild: false, isTraced: { true })
    XCTAssertTrue(c.isDebuggerAttached())
    XCTAssertEqual(c.getReasons(), ["Debugger attached via sysctl"])
  }

  func testDebugBuildSkipsDetection() {
    let c = DebuggerChecker(skipInDebugBuild: true, isTraced: { true })
    XCTAssertFalse(c.isDebuggerAttached())
    XCTAssertTrue(c.getReasons().isEmpty)
  }

  func testTracedProbeIsNotCalledWhenSkipped() {
    var called = false
    let c = DebuggerChecker(skipInDebugBuild: true, isTraced: { called = true; return true })
    _ = c.isDebuggerAttached()
    _ = c.getReasons()
    XCTAssertFalse(called)
  }

  func testSystemProbeIsCallableAndStable() {
    XCTAssertEqual(DebuggerChecker.systemIsTraced(), DebuggerChecker.systemIsTraced())
  }

  func testDefaultCheckerMatchesBuildConfiguration() {
    if DebuggerChecker.isDebugBuild {
      XCTAssertFalse(DebuggerChecker().isDebuggerAttached())
    }
  }
}

// MARK: - HookFrameworkChecker

final class HookFrameworkCheckerTests: XCTestCase {
  private func checker(symbols: Set<String> = [], malloc: UInt? = 0x1_8000_0000_0) -> HookFrameworkChecker {
    HookFrameworkChecker(hookSymbolExists: { symbols.contains($0) }, mallocAddress: { malloc })
  }

  func testClean() {
    let c = checker()
    XCTAssertFalse(c.detectHookFramework())
    XCTAssertFalse(c.detectFunctionHook())
    XCTAssertTrue(c.getReasons().isEmpty)
  }

  func testSubstrateSymbol() {
    let c = checker(symbols: ["MSHookFunction"])
    XCTAssertTrue(c.detectHookFramework())
    XCTAssertEqual(c.getReasons(), ["Hook framework detected"])
  }

  func testFishhookSymbol() {
    XCTAssertTrue(checker(symbols: ["fishhook"]).detectHookFramework())
  }

  func testUnrelatedSymbol() {
    XCTAssertFalse(checker(symbols: ["printf"]).detectHookFramework())
  }

  func testLowMallocAddressIsHook() {
    let c = checker(malloc: 0x1000)
    XCTAssertTrue(c.detectFunctionHook())
    XCTAssertEqual(c.getReasons(), ["Function hook detected"])
  }

  func testBoundaryAddress() {
    XCTAssertTrue(checker(malloc: 0xFFFF_FFFF).detectFunctionHook())
    XCTAssertFalse(checker(malloc: 0x1_0000_0000).detectFunctionHook())
  }

  func testZeroAddressIsHook() {
    XCTAssertTrue(checker(malloc: 0).detectFunctionHook())
  }

  func testUnresolvedMallocIsIgnored() {
    XCTAssertFalse(checker(malloc: nil).detectFunctionHook())
  }

  func testBothSignals() {
    XCTAssertEqual(checker(symbols: ["MSHookFunction"], malloc: 1).getReasons().count, 2)
  }

  func testSystemImplementations_cleanProcess() {
    XCTAssertFalse(HookFrameworkChecker.systemSymbolExists("definitely_not_a_symbol_xyz"))
    XCTAssertNotNil(HookFrameworkChecker.systemMallocAddress())
    XCTAssertFalse(HookFrameworkChecker().detectFunctionHook(), "real malloc must not look hooked")
  }
}

// MARK: - FridaChecker

final class FridaCheckerTests: XCTestCase {
  private func checker(
    images: [String] = ["/usr/lib/libSystem.B.dylib"],
    threads: [String] = ["main", "com.apple.uikit.eventfetch-thread"],
    symbols: Set<String> = [],
    files: Set<String> = [],
    port: Bool = false
  ) -> FridaChecker {
    FridaChecker(
      imageNames: { images },
      threadNames: { threads },
      symbolExists: { symbols.contains($0) },
      fileExists: { files.contains($0) },
      portOpen: { _ in port }
    )
  }

  func testClean() {
    let c = checker()
    XCTAssertFalse(c.isFridaDetected())
    XCTAssertTrue(c.getReasons().isEmpty)
  }

  func testEveryFridaImageNameIsDetected() {
    for name in ["/x/Frida.framework/Frida", "/tmp/frida-agent-64.dylib", "/var/FridaGadget.dylib", "/X/FRIDA"] {
      XCTAssertEqual(checker(images: [name]).getReasons(), ["Frida library loaded"], name)
    }
  }

  func testFridaThreadNames() {
    for t in ["gum-js-loop", "frida-main-loop", "GUM-Worker", "Frida", "gum-js"] {
      XCTAssertEqual(checker(threads: [t]).getReasons(), ["Frida thread detected"], t)
    }
  }

  func testEachFridaSymbolIsDetected() {
    for sym in ["frida_agent_main", "gum_script_backend_create", "gum_init", "frida"] {
      XCTAssertEqual(checker(symbols: [sym]).getReasons(), ["Frida symbols detected"], sym)
    }
  }

  func testFridaDynamicLibPaths() {
    for p in ["/usr/lib/frida", "/Library/MobileSubstrate/DynamicLibraries/frida"] {
      XCTAssertEqual(checker(files: [p]).getReasons(), ["Frida dynamic libraries detected"], p)
    }
  }

  func testOpenPort() {
    XCTAssertEqual(checker(port: true).getReasons(), ["Frida default port 27042 open"])
  }

  func testPortCheckedIsFridaDefault() {
    var asked: Int?
    let c = FridaChecker(
      imageNames: { [] }, threadNames: { [] }, symbolExists: { _ in false },
      fileExists: { _ in false }, portOpen: { asked = $0; return false })
    _ = c.getReasons()
    XCTAssertEqual(asked, 27042)
  }

  func testAllSignals() {
    let c = checker(images: ["frida-agent"], threads: ["gum-js"], symbols: ["gum_init"],
                    files: ["/usr/lib/frida"], port: true)
    XCTAssertEqual(c.getReasons().count, 5)
  }

  func testEmptyEnvironment() {
    let c = checker(images: [], threads: [])
    XCTAssertFalse(c.isFridaDetected())
  }

  func testUnrelatedNamesAreIgnored() {
    let c = checker(images: ["/usr/lib/libobjc.A.dylib"], threads: ["com.apple.NSURLSession-work"])
    XCTAssertFalse(c.isFridaDetected())
  }

  func testUnrelatedThreadNamesContainingGumAreIgnored() {
    for t in ["bubblegum-worker", "gumbo", "com.apple.gum"] {
      XCTAssertFalse(checker(threads: [t]).isFridaDetected(), t)
    }
  }

  func testSystemImplementations() {
    let images = FridaChecker.systemImageNames()
    XCTAssertFalse(images.isEmpty)
    XCTAssertFalse(images.contains { $0.lowercased().contains("frida") })
    XCTAssertFalse(FridaChecker.systemSymbolExists("frida_agent_main"))
    XCTAssertFalse(FridaChecker.systemThreadNames().contains { $0.lowercased().contains("frida") })
  }

  func testSystemThreadNamesSeesNamedThread() {
    let exp = expectation(description: "thread named")
    let release = DispatchSemaphore(value: 0)
    let t = Thread {
      pthread_setname_np("probe-thread-xyz")
      exp.fulfill()
      release.wait()
    }
    t.start()
    wait(for: [exp], timeout: 2)
    XCTAssertTrue(FridaChecker.systemThreadNames().contains("probe-thread-xyz"))
    release.signal()
  }
}

// MARK: - TCPCheck

final class TCPCheckTests: XCTestCase {
  private func listen() -> (fd: Int32, port: Int)? {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = 0
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    let bound = withUnsafePointer(to: &addr) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }
    guard bound == 0, Darwin.listen(fd, 4) == 0 else { close(fd); return nil }
    var out = sockaddr_in()
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &out) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
    }
    return (fd, Int(UInt16(bigEndian: out.sin_port)))
  }

  func testOpenPortIsDetected() throws {
    let server = try XCTUnwrap(listen())
    defer { close(server.fd) }
    XCTAssertTrue(TCPCheck.connect(port: server.port))
  }

  func testClosedPortIsNotDetected() throws {
    let server = try XCTUnwrap(listen())
    let port = server.port
    close(server.fd)
    XCTAssertFalse(TCPCheck.connect(port: port))
  }

  func testPortClosedAfterwardsIsNotDetected() throws {
    let server = try XCTUnwrap(listen())
    XCTAssertTrue(TCPCheck.connect(port: server.port))
    let port = server.port
    close(server.fd)
    XCTAssertFalse(TCPCheck.connect(port: port))
  }

  func testPortZeroIsNotDetected() {
    XCTAssertFalse(TCPCheck.connect(port: 0))
  }

  private func openDescriptorCount() -> Int {
    (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? 0
  }

  func testRepeatedChecksDoNotLeakDescriptors() throws {
    let server = try XCTUnwrap(listen())
    defer { close(server.fd) }
    let before = openDescriptorCount()
    for _ in 0..<100 {
      XCTAssertTrue(TCPCheck.connect(port: server.port))
      let accepted = accept(server.fd, nil, nil) // drain so the backlog never fills
      if accepted >= 0 { close(accepted) }
    }
    XCTAssertLessThanOrEqual(openDescriptorCount(), before + 1)

    let closed = try XCTUnwrap(listen())
    let port = closed.port
    close(closed.fd)
    let beforeClosed = openDescriptorCount()
    for _ in 0..<100 { XCTAssertFalse(TCPCheck.connect(port: port)) }
    XCTAssertLessThanOrEqual(openDescriptorCount(), beforeClosed + 1)
  }

  /// A listener that never accepts fills its backlog; a blocking connect would then hang
  /// for ~a minute and stall the watchdog.
  func testUnresponsiveListenerDoesNotBlock() throws {
    let server = try XCTUnwrap(listen())
    defer { close(server.fd) }
    Darwin.listen(server.fd, 0)

    var fillers: [Int32] = []
    defer { fillers.forEach { close($0) } }
    for _ in 0..<64 {
      let fd = socket(AF_INET, SOCK_STREAM, 0)
      _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
      var addr = sockaddr_in()
      addr.sin_family = sa_family_t(AF_INET)
      addr.sin_port = in_port_t(server.port).bigEndian
      addr.sin_addr.s_addr = inet_addr("127.0.0.1")
      _ = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
      }
      fillers.append(fd)
    }

    let start = Date()
    _ = TCPCheck.connect(port: server.port, timeoutMs: 100)
    XCTAssertLessThan(Date().timeIntervalSince(start), 2.0, "connect must honour its timeout")
  }

  func testOutOfRangePortsAreRejected() {
    XCTAssertFalse(TCPCheck.connect(port: -1))
    XCTAssertFalse(TCPCheck.connect(port: 65536))
    XCTAssertFalse(TCPCheck.connect(port: Int.max))
  }
}

// MARK: - AdvancedSecurityChecker

final class AdvancedSecurityCheckerTests: XCTestCase {
  private func checker(env: [String: String] = [:], images: [String] = [], skipDyld: Bool = false) -> AdvancedSecurityChecker {
    AdvancedSecurityChecker(environment: { env }, imageNames: { images }, skipDyldCheck: skipDyld)
  }

  func testDyldInjectionVariables() {
    for v in ["DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"] {
      XCTAssertTrue(checker(env: [v: "/tmp/x.dylib"]).detectDYLDInjection(), v)
    }
  }

  func testNoDyldVariables() {
    XCTAssertFalse(checker(env: ["HOME": "/"]).detectDYLDInjection())
    XCTAssertFalse(checker().detectDYLDInjection())
  }

  func testDyldCheckSkippedInDebugBuilds() {
    XCTAssertFalse(checker(env: ["DYLD_INSERT_LIBRARIES": "x"], skipDyld: true).detectDYLDInjection())
  }

  func testUnrelatedDyldVariableIgnored() {
    XCTAssertFalse(checker(env: ["DYLD_PRINT_STATISTICS": "1"]).detectDYLDInjection())
  }

  func testFridaMemoryNames() {
    for n in ["/x/frida-agent.dylib", "/x/libgum-js.dylib", "/x/Linjector", "/X/FRIDA"] {
      XCTAssertTrue(checker(images: [n]).detectFridaMemory(), n)
    }
  }

  func testFridaMemoryClean() {
    XCTAssertFalse(checker(images: ["/usr/lib/libSystem.dylib"]).detectFridaMemory())
    XCTAssertFalse(checker(images: []).detectFridaMemory())
  }

  func testReasonsIncludeInjectionAndFrida() {
    let c = checker(env: ["DYLD_INSERT_LIBRARIES": "x"], images: ["frida"])
    let reasons = c.getReasons()
    XCTAssertTrue(reasons.contains("Dynamic library injection detected"))
    XCTAssertTrue(reasons.contains("Frida memory pattern detected"))
  }

  func testRuntimeTrapAndSymbolsCleanInProcess() {
    let c = AdvancedSecurityChecker()
    XCTAssertFalse(c.detectFridaRuntimeTrap())
    XCTAssertFalse(c.detectCodeIntegrityViolation())
    XCTAssertFalse(c.detectMethodSwizzling())
  }

  func testMachExceptionPortDoesNotCrash() {
    _ = AdvancedSecurityChecker().detectMachExceptionPort()
  }

  func testBranchTargetDecodesForwardAndBackward() {
    // B +0x10 (imm26 = 4) at 0x1000 -> 0x1010
    XCTAssertEqual(AdvancedSecurityChecker.branchTarget(of: 0x1400_0004, at: 0x1000), 0x1010)
    // BL -4 (imm26 = 0x3FFFFFF) at 0x1000 -> 0xFFC... i.e. 0x1000 - 4
    XCTAssertEqual(AdvancedSecurityChecker.branchTarget(of: 0x97FF_FFFF, at: 0x1000), 0x0FFC)
    // B 0 -> itself
    XCTAssertEqual(AdvancedSecurityChecker.branchTarget(of: 0x1400_0000, at: 0x2000), 0x2000)
  }

  func testBranchTargetIgnoresNonBranches() {
    XCTAssertNil(AdvancedSecurityChecker.branchTarget(of: 0xD503_201F, at: 0x1000))  // NOP
    XCTAssertNil(AdvancedSecurityChecker.branchTarget(of: 0xD65F_03C0, at: 0x1000))  // RET
    XCTAssertNil(AdvancedSecurityChecker.branchTarget(of: 0xA9BF_7BFD, at: 0x1000))  // STP
    XCTAssertNil(AdvancedSecurityChecker.branchTarget(of: 0, at: 0x1000))
  }

  func testBranchWithinSameImageIsNotAHook() {
    let base: (UInt) -> UInt? = { _ in 0x1_8000_0000 }
    XCTAssertFalse(AdvancedSecurityChecker.isHookedPrologue(instruction: 0x1400_0004, at: 0x1000, imageBase: base))
  }

  func testBranchToOtherImageIsAHook() {
    let base: (UInt) -> UInt? = { $0 == 0x1000 ? 0x1_8000_0000 : 0x2_0000_0000 }
    XCTAssertTrue(AdvancedSecurityChecker.isHookedPrologue(instruction: 0x1400_0004, at: 0x1000, imageBase: base))
  }

  func testBranchIntoAnonymousMemoryIsAHook() {
    let base: (UInt) -> UInt? = { $0 == 0x1000 ? 0x1_8000_0000 : nil }
    XCTAssertTrue(AdvancedSecurityChecker.isHookedPrologue(instruction: 0x1400_0004, at: 0x1000, imageBase: base))
  }

  func testNonBranchPrologueIsNeverAHook() {
    XCTAssertFalse(AdvancedSecurityChecker.isHookedPrologue(instruction: 0xD503_237F, at: 0x1000, imageBase: { _ in nil }))
  }

  func testSystemImageBaseResolvesRealAndBogusAddresses() {
    let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "malloc")
    XCTAssertNotNil(AdvancedSecurityChecker.systemImageBase(UInt(bitPattern: symbol)))
    XCTAssertNil(AdvancedSecurityChecker.systemImageBase(0x10))
  }

  func testRealOpenIsNotReportedAsHooked() {
    XCTAssertFalse(AdvancedSecurityChecker().detectInlineHook())
  }

  func testInlineHookDoesNotCrashAndIsStable() {
    let c = AdvancedSecurityChecker()
    XCTAssertEqual(c.detectInlineHook(), c.detectInlineHook())
  }

  /// detectPtrace() must be idempotent: the watchdog calls it every few seconds, so a
  /// first call that leaves the process traced would make every later call report a debugger.
  func testPtraceIsIdempotent() {
    let c = AdvancedSecurityChecker()
    let first = c.detectPtrace()
    let second = c.detectPtrace()
    let third = c.detectPtrace()
    XCTAssertEqual(first, second)
    XCTAssertEqual(second, third)
  }

  func testPtraceDoesNotLeaveProcessTraced() {
    _ = AdvancedSecurityChecker().detectPtrace()
    XCTAssertFalse(DebuggerChecker.systemIsTraced(), "ptrace probe left P_TRACED set")
  }
}
