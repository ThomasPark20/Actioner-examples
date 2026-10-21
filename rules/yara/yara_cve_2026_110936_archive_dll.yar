import "hash"

rule CVE_2026_110936_Malicious_Archive_DLL
{
    meta:
        description = "Detects the malicious archive.dll used in CVE-2026-110936 exploitation of Siemens Software Center via DLL sideloading in the ROMULUS ClickFix campaign"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://productcert.siemens.com/news/2026/10/19/active-exploitation-of-cve-2026-110936-in-siemens-software-center"
        sha256 = "3fdcc7d7d049a89711fb31fb236940a1c5a09d899143ffd20c3c41fb1f2cf491"
        severity = "critical"
        caveat = "String artifacts (AllMyBasic, activate.bak, statinfosta.DB, etc.) are derived from campaign artifacts observed alongside this DLL, not confirmed as embedded strings within the binary itself. The SHA-256 hash match is the primary detection condition; strings provide secondary behavioral context for variant detection."

    strings:
        $msi_name = "AllMyBasic" ascii wide
        $artifact1 = "activate.bak" ascii wide
        $artifact2 = "statinfosta.DB" ascii wide
        $artifact3 = "SM Software Provisioning Service" ascii wide
        $path1 = "FTSuite" ascii wide
        $path2 = "ftc.uml" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            hash.sha256(0, filesize) == "3fdcc7d7d049a89711fb31fb236940a1c5a09d899143ffd20c3c41fb1f2cf491" or
            3 of them
        )
}
