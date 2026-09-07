rule Malware_RustCrate_ProcMacro1_BuildScript
{
    meta:
        description = "Detects malicious build.rs content from the proc-macro1 typosquatted Rust crate used in the August 2026 supply chain attack on arrayref, internment, and append-only-vec"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html"
        severity = "critical"

    strings:
        $dep_name = "proc-macro1" ascii
        $payload_unix = "/tmp/rust-setup" ascii
        $payload_win_ps = "rust-setup.ps1" ascii
        $payload_win_vbs = "rust-setup-launch.vbs" ascii
        $c2_ip = "23.254.165.112" ascii
        $c2_domain = "hwsrv-798836.hostwindsdns.com" ascii
        $binary_prefix = "rust-crate_0." ascii

    condition:
        filesize < 5MB and
        (
            ($dep_name and 2 of ($payload_*)) or
            (($c2_ip or $c2_domain) and 1 of ($payload_*)) or
            4 of them
        )
}

rule Malware_RustCrate_InfoStealer_Payload
{
    meta:
        description = "Detects the infostealer payload binary (rust-crate_0.x.0) dropped by the proc-macro1 supply chain attack, targeting Chromium browser credentials and crypto wallets"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html"
        severity = "critical"

    strings:
        $name1 = "rust-crate_0.1.0" ascii fullword
        $name2 = "rust-crate_0.2.0" ascii fullword
        $name3 = "rust-crate_0.3.0" ascii fullword
        $name4 = "rust-crate_0.4.0" ascii fullword
        $steal1 = "origin_url" ascii
        $steal2 = "username_value" ascii
        $c2 = "23.254.165.112" ascii
        $host = "hwsrv-798836.hostwindsdns.com" ascii

    condition:
        filesize < 10MB and
        (
            any of ($name*) and (1 of ($steal*) or $c2 or $host) or
            all of ($steal*) and ($c2 or $host)
        )
}
