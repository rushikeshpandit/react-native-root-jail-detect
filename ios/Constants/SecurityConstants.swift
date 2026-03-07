import Foundation

struct SecurityConstants {
  
    // MARK: - Known Jailbreak File Paths
  
  /**
   List of filesystem paths commonly associated with jailbroken devices.
   */
  
  static let jailbreakFilePaths: [String] = [
    
    // ── Package Managers ────────────────────────────────────────────────────
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Icy.app",
    "/Applications/RockApp.app",
    
    // ── Classic Jailbreak Apps ───────────────────────────────────────────────
    "/Applications/blackra1n.app",
    "/Applications/MxTube.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/Applications/IntelliScreen.app",
    "/Applications/FakeCarrier.app",
    "/Applications/FlyJB.app",
    
    // ── Shell / SSH ──────────────────────────────────────────────────────────
    "/bin/bash",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/sbin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/etc/ssh/sshd_config",
    "/private/etc/ssh/sshd_config",
    "/private/var/root/.ssh",
    "/private/var/root/.ssh/authorized_keys",
    "/var/root/.ssh",
    
    // ── APT / DPKG ───────────────────────────────────────────────────────────
    "/etc/apt",
    "/etc/apt/sources.list.d",
    "/var/cache/apt",
    "/var/log/apt",
    "/var/lib/cydia",
    "/var/lib/dpkg",
    "/var/lib/sileo",
    "/private/var/lib/apt",
    "/private/var/cache/apt",
    "/private/var/lib/cydia",
    "/private/var/lib/sileo",
    
    // ── Logs ─────────────────────────────────────────────────────────────────
    "/private/var/tmp/cydia.log",
    
    // ── Substrate / Injection ────────────────────────────────────────────────
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/CydiaSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/Library/Frameworks/CydiaSubstrate.framework",
    "/usr/lib/TweakInject",
    "/usr/lib/ellekit.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/libsubstitute.0.dylib",
    "/usr/lib/substitute-inserter",
    "/usr/lib/substitute-loader",
    "/usr/lib/substitute-hooker",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libhooker.dylib",
    
    // ── Tweaks ───────────────────────────────────────────────────────────────
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist",
    "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist",
    
    // ── Launch Daemons ───────────────────────────────────────────────────────
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    
    // ── Modern Jailbreaks ────────────────────────────────────────────────────
    "/.bootstrapped_electra",  // Namespaced — safe to keep
    // REMOVED: "/.bootstrapped" — too generic, not namespaced
    "/.cydia_no_stash",
    "/.installed_unc0ver",
    "/.installed_dopamine",
    "/.Fugu15",
    // REMOVED: "/jb" alone — too generic; sub-paths below are specific enough
    "/jb/lzma",
    "/jb/jailbreakd.plist",
    "/jb/offsets.plist",
    "/jb/amfid_payload.dylib",
    "/jb/libjailbreak.dylib",
    
    // ── Dopamine / var/jb (iOS 15–16 rootless) ──────────────────────────────
    "/var/jb",
    "/var/jb/usr/bin/apt",
    "/var/jb/usr/bin/dpkg",
    "/var/jb/usr/share/dpkg",
    "/var/jb/Library/dpkg",
    "/var/jb/private/etc/apt",
    "/var/jb/Library/MobileSubstrate",
    "/var/jb/usr/lib/TweakInject",
    "/var/jb/usr/lib/ellekit",
    "/var/jb/usr/lib/ellekit.dylib",
    "/var/jb/basebin",
    "/var/jb/basebin/jailbreakd",
    "/var/jb/.installed_palera1n",
    
    // ── XinaA15 ──────────────────────────────────────────────────────────────
    "/var/Liy",
    "/var/Liy/.installed_xina",
    
    // ── checkra1n / palera1n ─────────────────────────────────────────────────
    "/var/binpack",
    "/var/binpack/Applications/loader.app",
    "/usr/libexec/checkra1n",
    "/var/checkra1n",
    "/.palecursion",
    "/palera1n",
    
    // ── Serotonin / MDC (MacDirtyCow) ────────────────────────────────────────
    "/.serotonin_not_root",
    "/var/mobile/Serotonin",
    
    // ── Misaka (MDC-based tweak injector) ────────────────────────────────────
    "/var/mobile/Library/Misaka",
    "/var/mobile/Library/Misaka/Packages",
    
    // ── Frida ────────────────────────────────────────────────────────────────
    "/usr/sbin/frida-server",
    "/usr/bin/frida-server",
    "/usr/lib/frida",
    "/usr/lib/frida/frida-agent.dylib",
    "/usr/lib/frida/frida-gadget.dylib",
    "/usr/local/lib/node_modules/frida",
    
    // ── TrollStore ───────────────────────────────────────────────────────────
    "/var/mobile/Library/TrollStore",
    "/Applications/TrollStore.app",
    "/var/containers/Bundle/Application/.TrollStore",
    
    // ── Bypass Tools ─────────────────────────────────────────────────────────
    "/Library/PreferenceBundles/LibertyPref.bundle",
    "/Library/PreferenceBundles/ShadowPreferences.bundle",
    "/Library/PreferenceBundles/ABypassPrefs.bundle",
    "/Library/PreferenceBundles/FlyJBPrefs.bundle",
    "/Library/BawAppie/ABypass",
    "/var/mobile/Library/Preferences/ABPattern",
    "/var/mobile/Library/Preferences/me.jjolano.shadow.plist",
    
    // ── Preference Libraries ─────────────────────────────────────────────────
    "/Library/PreferenceBundles/Cephei.bundle",
    "/Library/PreferenceBundles/SubstitutePrefs.bundle",
    "/Library/PreferenceBundles/libhbangprefs.bundle",
    
    // ── User Data ────────────────────────────────────────────────────────────
    "/private/var/stash",
    "/private/var/mobile/Library/SBSettings/Themes",
  ]
  
    // MARK: - Jailbreak URL Schemes
  
  /**
   URL schemes used by popular jailbreak-related applications.
   */
  static let jailbreakURLSchemes: [String] = [
    "cydia://",
    "sileo://",
    "zbra://",
    "filza://",
    "activator://",
    "undecimus://",
  ]
  
    // MARK: - Restricted Paths
  
  /**
   Filesystem paths that are restricted on jailbroken devices.
   */
  static let restrictedPaths: [String] = [
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/libexec/cydia",
    "/usr/bin/cycript",
    "/usr/local/bin/cycript",
    "/usr/lib/libcycript.dylib",
  ]
}
