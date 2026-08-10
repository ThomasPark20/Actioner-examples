rule Malware_macOS_PamStealer_Rust_Payload
{
    meta:
        description = "Detects PamStealer macOS infostealer Rust-based Mach-O payload via distinctive strings including C2 endpoints, config identifiers, PAM authentication markers, and masquerading bundle identifiers"
        author = "Actioner"
        date = "2026-07-04"
        reference = "https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/"
        tlp = "WHITE"
        severity = "critical"
        hash = "36d46ac7123e0cef04f179d88e590891c7e7c64ec5a77df4512cb485e40286da"

    strings:
        $c2_domain = "avenger-sync.live" ascii wide
        $c2_endpoint = "/api/sync" ascii
        $c2_alt1 = "sync-master.online" ascii
        $c2_alt2 = "avngr.netlify.app" ascii

        $config_id = "avenger-config-v2" ascii
        $build_marker = "MacOSapp1" ascii

        $pam_start = "pam_start" ascii
        $pam_auth = "pam_authenticate" ascii
        $pam_end = "pam_end" ascii

        $bundle_fake1 = "com.apple.finder.core" ascii
        $bundle_fake2 = "com.apple.finder.monitor" ascii
        $bundle_fake3 = "com.apple.security.daemon" ascii

        $payload_name = "77617EA0" ascii
        $clipboard = "pbpaste" ascii
        $chacha = "ChaCha20" ascii

        $eth_rpc1 = "eth.drpc.org" ascii
        $eth_rpc2 = "ethereum-rpc.publicnode.com" ascii

    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA) and
        filesize < 20MB and
        (
            ($c2_domain) or
            ($config_id) or
            ($build_marker and 1 of ($bundle_fake*)) or
            (2 of ($pam_start, $pam_auth, $pam_end) and 1 of ($bundle_fake*)) or
            ($payload_name and 1 of ($bundle_fake*)) or
            (1 of ($c2_alt*) and 1 of ($bundle_fake*, $pam_start, $pam_auth)) or
            (4 of them)
        )
}

rule Malware_macOS_PamStealer_AppleScript_Dropper
{
    meta:
        description = "Detects PamStealer AppleScript dropper (Maccy.scpt) via characteristic strings including the fake Maccy branding, NSURLSession payload retrieval, and social engineering prompt text"
        author = "Actioner"
        date = "2026-07-04"
        reference = "https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $prompt = "Maccy wants to make changes" ascii wide
        $decoy = "is damaged and can't be opened" ascii wide
        $nsurl = "NSURLSession" ascii
        $jxa_marker = "ObjC.import" ascii

        $c2 = "avenger-sync.live" ascii
        $dist = "maccyapp.com" ascii
        $dist2 = "maccyapp.net" ascii

        $config = "avenger-config-v2" ascii
        $marker = ".Maccy" ascii

        $tz_ru = "Europe/Moscow" ascii
        $tz_by = "Europe/Minsk" ascii
        $tz_kz = "Asia/Almaty" ascii

    condition:
        filesize < 10MB and
        (
            ($prompt and ($nsurl or $jxa_marker)) or
            ($c2 and ($nsurl or $jxa_marker)) or
            (1 of ($dist, $dist2) and ($nsurl or $jxa_marker)) or
            ($config and $marker) or
            ($prompt and $decoy) or
            (2 of ($tz_ru, $tz_by, $tz_kz) and ($c2 or $config or 1 of ($dist, $dist2)))
        )
}
