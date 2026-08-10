rule Malware_CrashStealer_macOS_Infostealer
{
    meta:
        description = "Detects CrashStealer macOS infostealer via characteristic debug strings, bundle identifier spoofing, and encryption configuration artifacts"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://www.jamf.com/blog/crashstealer-macos-infostealer-analysis/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $bundle = "com.apple.crashreporter" ascii
        $salt = "panel_salt_v1" ascii
        $config = "config_crypto_salt" ascii
        $fallback = "using fallback salt" ascii
        $debug1 = "collectBrowserData" ascii
        $debug2 = "collectExtensions" ascii
        $debug3 = "collectSoftwareTargets" ascii
        $debug4 = "runFileSearcher" ascii
        $debug5 = "collectFirefoxExtensions" ascii
        $class = "MacOSData" ascii
        $filesearch = "FileSearcher::search" ascii
        $dropper_bundle = "dev.golove.velto" ascii
        $archive_prefix = ".zx_" ascii

    condition:
        filesize < 20MB and
        (
            ($bundle and $salt) or
            ($bundle and $config) or
            ($bundle and 3 of ($debug*)) or
            ($dropper_bundle and $archive_prefix) or
            ($salt and $fallback and 2 of ($debug*)) or
            (4 of ($debug*) and $class) or
            ($filesearch and $class and 2 of ($debug*))
        )
}
