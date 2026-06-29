import "pe"

rule Malware_SharkLoader_DLL
{
    meta:
        description = "Detects SharkLoader DLL (SystemSettings.dll) used in StrikeShark campaign via characteristic resource names and encrypted payload references"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://securelist.com/strikeshark-campaign/120326/"
        severity = "medium"

    strings:
        $res1 = "TELEMETRY" ascii wide
        $res2 = "VAULTSVCD" ascii wide
        $res3 = "UMRDPRDAT" ascii wide
        $file1 = "DscCoreR.mui" ascii wide
        $file2 = "SyncRes.dat" ascii wide
        $file3 = "SystemSettings.dll" ascii wide
        $alt1 = "GameInputInboxs32.mui" ascii wide
        $alt2 = "VistaCompat.nls" ascii wide
        $alt3 = "Ignored.Dat" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (2 of ($res*)) or
            ($file1 and $file2) or
            (1 of ($res*) and 2 of ($file*)) or
            (1 of ($res*) and 1 of ($alt*))
        )
}

rule Malware_SharkLoader_Dropper
{
    meta:
        description = "Detects SharkLoader dropper executables masquerading as legitimate installers (Google Update, Cisco AnyConnect) in the StrikeShark campaign"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://securelist.com/strikeshark-campaign/120326/"
        severity = "high"

    strings:
        $lure1 = "GoogleUpdateStepup" ascii wide
        $lure2 = "AnyConnect-win-4.10.04071-predeploy-k9" ascii wide
        $lure3 = "AutoUpdate.exe" ascii wide
        $res1 = "TELEMETRY" ascii wide
        $res2 = "VAULTSVCD" ascii wide
        $res3 = "UMRDPRDAT" ascii wide
        $path1 = "\\xwreg\\" ascii wide
        $path2 = "\\xgdf\\" ascii wide
        $path3 = "\\aswerf\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($lure*) and 1 of ($res*)) or
            (2 of ($res*) and 1 of ($path*))
        )
}
