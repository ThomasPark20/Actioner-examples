/*
 * Lazarus Operation Dream Job - YARA Rules (Combined)
 * Author: Actioner | Date: 2026-08-16
 * Reference: https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/
 *
 * Contains:
 *   1. APT_Lazarus_FudModule_v31 - FudModule v3.1 kernel-mode rootkit
 *   2. APT_Lazarus_Troy_Backdoor - Troy backdoor
 *   3. APT_Lazarus_SecurityPDF_Trojan - SecurityPDF trojanized MuPDF viewer
 */

import "pe"

rule APT_Lazarus_FudModule_v31 : lazarus rootkit
{
    meta:
        description = "Detects Lazarus FudModule v3.1 kernel-mode rootkit used in Operation Dream Job CVE-2026-68820 exploitation chain"
        author = "Actioner"
        date = "2026-08-16"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
        hash = "3b6378df8442e63a6ed7317075913e4720847a510d95022d4a8347b2637c245d"
        severity = "critical"

    strings:
        $s1 = "enable_god_mode passed" ascii wide
        $s2 = "FudModule" ascii wide
        $s3 = "VerifiedAndReputablePolicyState" ascii wide
        $s4 = "NtSetSystemInformation" ascii fullword
        $s5 = "DestroyEnv" ascii fullword

        $api1 = "ZwQuerySystemInformation" ascii fullword
        $api2 = "ObRegisterCallbacks" ascii fullword
        $api3 = "PsSetCreateProcessNotifyRoutine" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (2 of ($s*) or (1 of ($s*) and 2 of ($api*)))
}

rule APT_Lazarus_Troy_Backdoor : lazarus backdoor
{
    meta:
        description = "Detects Lazarus Troy backdoor deployed via SecurityPDF trojanized viewer in Operation Dream Job"
        author = "Actioner"
        date = "2026-08-16"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
        severity = "critical"

    strings:
        $pdb = "E:\\HK\\Tool_Module\\Troy_Handle\\1Troy_Create_Dll_Tool" ascii
        $cmd1 = "ZIPDOWNLOAD" ascii fullword
        $cmd2 = "DRIVES" ascii fullword
        $cmd3 = "DEFAULTSLEEP" ascii fullword
        $cmd4 = "GET_CONFIG" ascii fullword
        $cmd5 = "SET_CONFIG" ascii fullword
        $cmd6 = "CONNECTED" ascii fullword
        $marker = "This document is encrypted with sumatrapdf reader!!!!!!!!!!!!" ascii

        $net1 = "Compress-Archive" ascii
        $net2 = "RtlCreateUserThread" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($pdb or $marker or (3 of ($cmd*) and 1 of ($net*)))
}

rule APT_Lazarus_SecurityPDF_Trojan : lazarus trojan
{
    meta:
        description = "Detects SecurityPDF trojanized MuPDF viewer used by Lazarus to deliver Troy backdoor via XOR-encrypted PDFs"
        author = "Actioner"
        date = "2026-08-16"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
        hash1 = "743172aab606974b054a64561534ae66baa3a840657f79d7c6fa18350e8d45d1"
        hash2 = "db3d69b7eeda2e35e23006bf4b7e206281fce809584207214fc213f9bc30376d"
        severity = "high"

    strings:
        $marker = "This document is encrypted with sumatrapdf reader!!!!!!!!!!!!" ascii wide
        $temp_drop = "\\Temp\\new.exe" ascii wide
        $mupdf = "libmupdf" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $marker and ($temp_drop or $mupdf)
}
