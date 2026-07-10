import "pe"

rule Malware_PoisonX_BYOVD_Driver
{
    meta:
        description = "Detects the PoisonX malicious kernel driver used for BYOVD attacks to terminate security processes at the kernel level"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/"
        hash = "2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $guid = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $api1 = "ZwOpenProcess" ascii
        $api2 = "ZwTerminateProcess" ascii
        $devpath1 = "\\Device\\" ascii wide
        $devpath2 = "\\DosDevices\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $guid and
        $api1 and $api2 and
        1 of ($devpath*)
}

rule Ransomware_GodDamn_Hyadina
{
    meta:
        description = "Detects the GodDamn ransomware binary from the Hyadina threat group based on distinctive strings and file characteristics"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses"
        hash = "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ext1 = ".God8Damn" ascii wide
        $name1 = "encrypter-windows-gui-x86" ascii wide
        $name2 = "GodDamn" ascii wide
        $note1 = "qTox" ascii wide
        $ransom1 = "God8Damn" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($ext1 and 1 of ($name*)) or
            (2 of ($name*, $ransom1) and $note1) or
            ($ext1 and $note1)
        )
}
