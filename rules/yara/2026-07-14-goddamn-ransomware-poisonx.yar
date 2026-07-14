rule Malware_GodDamn_Ransomware_Encryptor
{
    meta:
        description = "Detects GodDamn ransomware encryptor binary by embedded strings including the distinctive .God8Damn file extension and ransomware GUI indicators. GodDamn is a Beast ransomware rebrand operated by the Hyadina group."
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ext1 = ".God8Damn" ascii wide
        $name1 = "encrypter-windows-gui" ascii wide
        $name2 = "GodDamn" ascii wide
        $gui1 = "encrypter" ascii wide
        $func1 = "encrypt" ascii wide nocase
        $func2 = "ransom" ascii wide nocase
        $func3 = "decrypt" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            ($ext1 and 1 of ($name*, $gui1)) or
            ($ext1 and 2 of ($func*))
        )
}

/* audit: yarac exit code 0. Overlap note: the Malware_PoisonX_BYOVD_Driver YARA
   rule from the GentleKiller report (2026-06-23) covers the PoisonX driver
   (G11.sys) itself. This rule covers the user-mode defense evasion component.
   Inconsistent .exe suffixes in $proc* strings: some include .exe (avp.exe,
   ekrn.exe) while others use bare service names (CSFalconService, MsMpEng,
   SentinelAgent, etc.). This is intentional -- the binary contains both forms
   as it targets both process names and service names. */
rule Malware_GodDamn_Defense_Evasion_Tool
{
    meta:
        description = "Detects the GodDamn user-mode defense evasion tool that works alongside the PoisonX kernel driver. The tool masquerades as symantec.exe and terminates security processes and removes API hooks to blind endpoint security before ransomware deployment."
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dev = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $drv = "g11.sys" ascii wide nocase
        $api1 = "ZwOpenProcess" ascii
        $api2 = "ZwTerminateProcess" ascii
        $api3 = "NtOpenProcess" ascii
        $api4 = "NtTerminateProcess" ascii
        $proc01 = "CSFalconService" ascii wide
        $proc02 = "MsMpEng" ascii wide
        $proc03 = "SentinelAgent" ascii wide
        $proc04 = "SophosHealth" ascii wide
        $proc05 = "avp.exe" ascii wide
        $proc06 = "ekrn.exe" ascii wide
        $proc07 = "CylanceSvc" ascii wide
        $proc08 = "cbdefense" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($dev and 3 of ($proc*)) or
            ($drv and 1 of ($api*) and 3 of ($proc*))
        )
}
