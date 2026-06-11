/*
    GreatXML BitLocker Bypass - YARA Detection Rules
    Report: summaries/2026-06-11-greatxml-bitlocker-bypass.md
    Generated: 2026-06-11 v1.1 FINAL
*/

rule Exploit_GreatXML_BitLocker_Bypass
{
    meta:
        description = "Detects the GreatXML exploit tool that abuses Microsoft Defender offline scan artifacts to bypass BitLocker encryption via crafted unattend.xml and Recovery directory planted on the recovery partition"
        author = "Actioner"
        date = "2026-06-11"
        reference = "https://github.com/MSNightmare/GreatXML"
        severity = "critical"
        tlp = "WHITE"
        note = "Public PoC is deliberately incomplete; final exploit component withheld by researcher"

    strings:
        $name1 = "GreatXML" ascii wide
        $name2 = "greatxml" ascii wide nocase

        $xml1 = "unattend.xml" ascii wide nocase
        $xml2 = "unattend" ascii wide
        $xml3 = "<settings pass=" ascii wide

        $recov1 = "Recovery\\WindowsRE" ascii wide
        $recov2 = "\\Recovery\\" ascii wide
        $recov3 = "WinRE" ascii wide

        $defender1 = "Windows Defender" ascii wide nocase
        $defender2 = "OfflineScan" ascii wide
        $defender3 = "WdBoot" ascii wide
        $defender4 = "MpCmdRun" ascii wide

        $author1 = "Nightmare" ascii wide
        $author2 = "MSNightmare" ascii wide
        $author3 = "Chaotic Eclipse" ascii wide
        $author4 = "Dead Eclipse" ascii wide

        $bitlocker1 = "BitLocker" ascii wide nocase
        $bitlocker2 = "FVE" ascii wide

    condition:
        filesize < 5MB and (
            (
                ($name1 or $name2) and (1 of ($xml*) or 1 of ($recov*))
            ) or
            (
                2 of ($author*) and (1 of ($xml*) or 1 of ($recov*)) and 1 of ($defender*)
            ) or
            (
                1 of ($name*) and 1 of ($defender*) and 1 of ($bitlocker*)
            )
        )
}

rule Exploit_GreatXML_Unattend_XML_Payload
{
    meta:
        description = "Detects crafted unattend.xml files consistent with GreatXML exploit payload that targets WinRE to bypass BitLocker and spawn SYSTEM shell. Requires PoC-specific anchor strings to reduce false positives from legitimate enterprise imaging answer files."
        author = "Actioner"
        date = "2026-06-11"
        reference = "https://github.com/MSNightmare/GreatXML"
        severity = "high"
        tlp = "WHITE"
        note = "Hunt-only rule (low confidence). Legitimate enterprise unattend.xml files with RunSynchronous+cmd/powershell are common. Manual triage required. Public PoC is deliberately incomplete."

    strings:
        $xml_header = "<?xml" ascii wide nocase
        $unattend_ns = "urn:schemas-microsoft-com:unattend" ascii wide nocase
        $settings = "<settings pass=" ascii wide nocase

        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell" ascii wide nocase

        $winre1 = "windowsPE" ascii wide nocase
        $winre2 = "offlineServicing" ascii wide nocase

        $shell1 = "RunSynchronous" ascii wide nocase
        $shell2 = "RunSynchronousCommand" ascii wide nocase

        $poc_anchor1 = "GreatXML" ascii wide nocase
        $poc_anchor2 = "MSNightmare" ascii wide nocase
        $poc_anchor3 = "Nightmare" ascii wide
        $poc_anchor4 = "BitLocker" ascii wide nocase
        $poc_anchor5 = "Recovery\\WindowsRE" ascii wide

    condition:
        filesize < 500KB and
        $xml_header and
        $unattend_ns and
        1 of ($settings, $winre*) and
        1 of ($cmd*) and
        1 of ($shell*) and
        1 of ($poc_anchor*)
}
