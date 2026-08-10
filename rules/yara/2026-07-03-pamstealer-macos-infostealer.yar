// Actioner - PamStealer macOS Infostealer YARA Rules
// Date: 2026-07-03
// Reference: https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/

rule PamStealer_macOS_Campaign_Indicators
{
    meta:
        description = "Detects PamStealer campaign artifacts via distinctive string indicators including C2 markers, config identifiers, and fake Apple bundle paths"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/"
        severity = "high"

    strings:
        $marker1 = "MacOSapp1" ascii
        $marker2 = "avenger-config-v2" ascii
        $marker3 = "avenger-sync" ascii
        $c2_path = "/api/sync" ascii
        $pam1 = "pam_start" ascii
        $pam2 = "pam_authenticate" ascii
        $pam3 = "pam_end" ascii
        $bundle1 = "com.apple.finder.core" ascii
        $bundle2 = "com.apple.finder.monitor" ascii
        $bundle3 = "com.apple.security.daemon" ascii
        $helper = "System Settings" ascii wide

    condition:
        filesize < 10MB and
        (
            ($marker1 and $c2_path) or
            ($marker2 and ($marker1 or $marker3 or 1 of ($pam*) or 1 of ($bundle*))) or
            (2 of ($pam*) and 1 of ($bundle*)) or
            ($marker3 and 1 of ($bundle*)) or
            ($helper and 1 of ($bundle*))
        )
}

rule PamStealer_macOS_Rust_Stealer
{
    meta:
        description = "Detects PamStealer Rust-based macOS infostealer via PAM API usage combined with clipboard theft and C2 markers"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/"
        severity = "critical"

    strings:
        $pam1 = "pam_start" ascii
        $pam2 = "pam_authenticate" ascii
        $pam3 = "pam_end" ascii
        $clip = "pbpaste" ascii
        $c2_marker = "MacOSapp1" ascii
        $c2_config = "avenger-config-v2" ascii
        $c2_domain = "avenger-sync.live" ascii
        $bundle_path1 = "com.apple.finder.core" ascii
        $bundle_path2 = "com.apple.finder.monitor" ascii
        $prompt = "wants to make changes" ascii wide

    condition:
        (uint32(0) == 0xBEBAFECA or uint32(0) == 0xFEEDFACF) and
        filesize < 10MB and
        (
            (all of ($pam*) and $clip) or
            ($c2_marker and $c2_config) or
            ($c2_domain and 1 of ($bundle_path*)) or
            ($prompt and 1 of ($pam*))
        )
}
