rule Ransomware_GodDamn_Encrypter
{
    meta:
        description = "Detects GodDamn ransomware encrypter (Beast/Monster rebrand by Hyadina group) via the distinctive .God8Damn file extension string embedded in the PE binary"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ext1 = ".God8Damn" ascii wide
        $ext2 = "God8Damn" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        any of ($ext*)
}

rule Malware_PoisonX_BYOVD_Driver_GodDamn
{
    meta:
        description = "Detects PoisonX kernel driver (g11.sys) used by GodDamn ransomware and GentleKiller to terminate EDR/AV processes at kernel level. The driver is Microsoft-signed and uses a unique device GUID for IOCTL communication."
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dev = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $api1 = "ZwOpenProcess" ascii
        $api2 = "ZwTerminateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $dev and
        ($api1 and $api2)
}
