/*
 * Actioner Detection Rules - BGP Hijack Virtualizor Supply Chain (2026-09-03)
 * Source: /home/user/Actioner-examples/summaries/2026-09-03-bgp-hijack-virtualizor-supply-chain.md
 */

import "hash"

// YARA-01: Payload Hash Match (jre-runtime.dat)
rule Virtualizor_BGP_Hijack_Payload_JRE_Runtime
{
    meta:
        description = "Detects the malicious jre-runtime.dat payload dropped by compromised Virtualizor update"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.virtualizor.com/blog/security-incident-bgp-hijacking/"
        hash = "b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7"
        severity = "critical"

    condition:
        filesize < 50MB and
        hash.sha256(0, filesize) == "b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7"
}

// YARA-02: Modified PHP Files with C2 Strings
rule Virtualizor_BGP_Hijack_Modified_PHP_Files
{
    meta:
        description = "Detects Virtualizor PHP files containing injected C2 domain strings from the BGP hijack supply chain attack"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html"
        severity = "critical"

    strings:
        $c2_1 = "cdn.nerat.cc" ascii wide
        $c2_2 = "connect.ne-rat.xyz" ascii wide
        $payload_url = "cdn.nerat.cc/installer/widdow.jar" ascii wide
        $marker_1 = "jre-runtime.dat" ascii wide
        $marker_2 = ".vz_svc_done" ascii wide
        $marker_3 = "widdow.jar" ascii wide
        $service = "java-jre-update.service" ascii wide

    condition:
        filesize < 5MB and
        (
            any of ($c2_*) or
            ($payload_url) or
            (2 of ($marker_*)) or
            ($service and any of ($marker_*))
        )
}

// YARA-03: Widdow JAR Payload
rule Virtualizor_BGP_Hijack_Widdow_JAR
{
    meta:
        description = "Detects the widdow.jar Java payload used in the Virtualizor BGP hijack supply chain attack"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html"
        severity = "critical"

    strings:
        $pk_header = { 50 4B 03 04 }
        $c2_1 = "cdn.nerat.cc" ascii
        $c2_2 = "connect.ne-rat.xyz" ascii
        $c2_3 = "ne-rat" ascii
        $java_class = ".class" ascii

    condition:
        $pk_header at 0 and
        filesize < 50MB and
        $java_class and
        any of ($c2_*)
}

// YARA-04: Attacker SSH Key Injection
rule Virtualizor_BGP_Hijack_SSH_Key_Injection
{
    meta:
        description = "Detects the attacker-controlled SSH ed25519 public key injected into root authorized_keys by the malicious Virtualizor update"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html"
        severity = "critical"

    strings:
        $ssh_key = "AAAAC3NzaC1lZDI1NTE5AAAAIP13pPAm5jmInLQYD3XNb3HwrW4cAKDcphoT4kSKrnte" ascii

    condition:
        filesize < 1MB and
        $ssh_key
}
