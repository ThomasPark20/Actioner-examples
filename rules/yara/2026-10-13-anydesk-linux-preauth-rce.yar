rule Vuln_AnyDesk_Linux_CVE_2026_109390 : vulnerability
{
    meta:
        description = "Detects AnyDesk Linux binaries in the version range affected by CVE-2026-109390 (pre-auth heap buffer overflow, 8.0.0-8.0.2). The mode-5 stream handler integer overflow is present in these builds."
        author = "Actioner"
        date = "2026-10-13"
        reference = "https://github.com/v12-security/pocs/tree/main/anydesk"
        severity = "critical"

    strings:
        $anydesk_str = "AnyDesk" ascii wide
        $linux_elf = { 7F 45 4C 46 }

        $vuln_v800 = "8.0.0" ascii
        $vuln_v801 = "8.0.1" ascii
        $vuln_v802 = "8.0.2" ascii

        $anynet = "anynet" ascii
        $ad_proto = "ad.session" ascii
        $ad_stream = "ad.stream" ascii

    condition:
        $linux_elf at 0 and
        $anydesk_str and
        1 of ($vuln_v8*) and
        1 of ($anynet, $ad_proto, $ad_stream)
}
