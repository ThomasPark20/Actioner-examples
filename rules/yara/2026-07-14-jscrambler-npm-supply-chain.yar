rule Malware_Jscrambler_IronWorm_Payload
{
    meta:
        description = "Detects the IronWorm Rust-based infostealer payload delivered via the compromised jscrambler npm package (July 2026 supply-chain attack)"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html"
        hash = "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd"
        hash = "b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903"
        hash = "c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd"
        severity = "critical"
        confidence = "medium"
        tlp = "WHITE"

    strings:
        $c2_1 = "37.27.122.124" ascii
        $c2_2 = "57.128.246.79" ascii
        $exfil = "temp.sh" ascii
        $tor_1 = "check.torproject.org" ascii
        $tor_2 = "archive.torproject.org" ascii
        $rust_1 = "rustls" ascii
        $rust_2 = "chacha20" ascii nocase
        $rust_3 = "poly1305" ascii nocase

    condition:
        filesize < 50MB and
        (
            (2 of ($c2_*) and $exfil) or
            (1 of ($c2_*) and 2 of ($tor_*)) or
            (1 of ($c2_*) and 2 of ($rust_*) and $exfil)
        )
}
