/*
 * GodDamn Ransomware with PoisonX Driver - YARA Detection Rules
 * Report: /home/user/Actioner-examples/summaries/2026-07-13-goddamn-ransomware-poisonx.md
 *
 * Coverage gap: 15+ PoisonX driver variants exist (all Microsoft-signed).
 * Append additional variant hashes and strings to Driver_PoisonX_EDRKiller
 * as they become available from threat intelligence feeds.
 */

rule Ransomware_GodDamn_Encryptor
{
    meta:
        description = "Detects GodDamn ransomware encryptor binary via distinctive strings (.God8Damn extension, original filename)"
        author = "Actioner"
        date = "2026-07-13"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69"
        severity = "critical"

    strings:
        $ext = ".God8Damn" ascii wide
        $name = "encrypter-windows-gui-x86" ascii wide
        $family1 = "GodDamn" ascii wide
        $family2 = "Beast" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($ext or ($name and 1 of ($family*)))
}

rule Driver_PoisonX_EDRKiller
{
    meta:
        description = "Detects the PoisonX malicious kernel driver used to terminate security product processes via BYOVD technique with IOCTL 0x22E010"
        author = "Actioner"
        date = "2026-07-13"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d"
        severity = "critical"

    strings:
        $guid = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide nocase
        $drv_name = "g11.sys" ascii wide
        $nt_func1 = "ZwOpenProcess" ascii
        $nt_func2 = "ZwTerminateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($guid or ($drv_name and 1 of ($nt_func*)))
}
