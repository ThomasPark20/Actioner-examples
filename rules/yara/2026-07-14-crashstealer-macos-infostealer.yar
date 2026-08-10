rule Malware_CrashStealer_macOS_Infostealer
{
    meta:
        description = "Detects CrashStealer macOS infostealer via characteristic strings found in the binary, including its hardcoded encryption salt, staging paths, credential validation command, and bundle identifier"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $salt = "panel_salt_v1" ascii
        $path1 = "/tmp/.CrashReporter/" ascii
        $path2 = ".cache/com.apple.crashreporter" ascii
        $path3 = ".cache/.sys_auth" ascii
        $bundle = "com.apple.crashreporter" ascii
        $plist = "com.apple.crashreporter.helper" ascii
        $dscl = "dscl" ascii
        $authonly = "-authonly" ascii
        $zx_prefix = ".zx_" ascii
        $c2_ip = "179.43.166.242" ascii
        $c2_domain = "endpoint-api-v1" ascii
        // NOTE: $exit45 matches the x86_64 encoding of 'mov eax, 45' (exit code
        // on debugger detection). ARM64 uses a different instruction encoding
        // (e.g., MOV W0, #0x2D / MOV X8, #0x1 / SVC #0) so this pattern will
        // NOT match ARM64 (Apple Silicon) builds of the malware.
        $exit45 = { B8 2D 00 00 00 }

    condition:
        filesize < 10MB and
        (
            ($salt and 2 of ($path*)) or
            ($bundle and $plist and 1 of ($path*)) or
            ($dscl and $authonly and 1 of ($path*)) or
            (4 of them)
        )
}

rule Malware_CrashStealer_Dropper_Werkbit
{
    meta:
        description = "Detects the Werkbit dropper used to deliver CrashStealer macOS infostealer, based on distribution infrastructure strings and staging behavior"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $werkbit = "werkbit" ascii nocase
        $veltod = "veltod" ascii
        $sys_cache = "sys.cache" ascii
        $github = "mgothiclove" ascii
        $endpoint = "endpoint-api-v1" ascii
        $c2 = "179.43.166.242" ascii

    condition:
        filesize < 20MB and
        (
            ($werkbit and ($veltod or $sys_cache)) or
            ($github and $sys_cache) or
            ($endpoint and 1 of ($werkbit, $veltod, $c2))
        )
}
