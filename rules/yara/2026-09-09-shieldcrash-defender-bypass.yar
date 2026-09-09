rule Exploit_CVE_2026_69414_ShieldCrash
{
    meta:
        description = "Detects the ShieldCrash PoC exploit binary (CVE-2026-69414 patch bypass) via characteristic strings unique to this tool"
        author = "Actioner"
        date = "2026-09-09"
        reference = "https://github.com/MSNightmare/ShieldCrash"
        severity = "critical"
        mitre_attack = "T1068"

    strings:
        $dir = "ShieldCrash_" ascii wide
        $bern = "BERN" ascii wide fullword
        $bern2 = ".BERN2" ascii wide
        $flubber = "Flubber" ascii wide fullword
        $provider_guid = "{B196E670-59C7-4D41-9637-C62D80541321}" ascii wide
        $wd_shadow = "WD_SHADOW_" ascii wide
        $wd_target = "WD_TARGET_" ascii wide
        $clfs = "\\CLFS\\" ascii wide
        $warden = "Warden.dll" ascii wide
        $mp_scan = "MpScanStart" ascii
        $mp_clean = "MpCleanStart" ascii
        $mp_threat = "MpThreatEnumerate" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($dir and $flubber) or
            ($dir and $bern and 2 of ($wd_shadow, $wd_target, $clfs)) or
            ($provider_guid and 2 of ($mp_scan, $mp_clean, $mp_threat)) or
            (5 of them)
        )
}
