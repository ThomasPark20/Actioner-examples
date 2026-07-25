import "pe"

rule UAC0099_LUNCHPOKE_NppExport_Plugin
{
    meta:
        description = "Detects the LUNCHPOKE malicious Notepad++ plugin (NppExport.dll) used by UAC-0099 to establish persistence and deploy BURNYBEAR loader"
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $npp_export1 = "NppExport" ascii wide
        $schtasks = "schtasks" ascii wide nocase
        $updater_rar = "updater.rar" ascii wide
        $remote_lib = "RemoteLibUpdater" ascii wide
        $init_test = "InitTest.dll" ascii wide
        $setup_arg = "setup" ascii wide
        $nodisplay = "nodisplay" ascii wide
        $public_path = "\\Users\\Public\\" ascii wide
        $wallpapers = "\\Wallpapers\\Background.exe" ascii wide
        $task_path = "W1n3r-U09oTy-Ap5" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($npp_export1 and $schtasks and ($updater_rar or $remote_lib)) or
            ($task_path) or
            ($wallpapers and $schtasks) or
            ($public_path and $remote_lib and $init_test) or
            (4 of ($schtasks, $updater_rar, $remote_lib, $init_test, $setup_arg, $nodisplay))
        )
}

rule UAC0099_BURNYBEAR_Loader
{
    meta:
        description = "Detects the BURNYBEAR loader (RemoteLibUpdater.exe) used by UAC-0099 that loads MATCHBOIL.V2 and includes anti-analysis resource exhaustion logic"
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://cert.gov.ua/article/6318634"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $name1 = "RemoteLibUpdater" ascii wide fullword
        $dll_load = "InitTest.dll" ascii wide
        $arg_setup = "setup" ascii wide
        $arg_nodisplay = "nodisplay" ascii wide
        $resource_exhaust1 = "System.Threading" ascii wide
        $resource_exhaust2 = "MemoryStream" ascii wide
        $dotnet1 = "_CorExeMain" ascii fullword
        $dotnet2 = "mscoree.dll" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($name1 and $dll_load and ($arg_setup or $arg_nodisplay)) or
            ($name1 and 1 of ($dotnet*) and 1 of ($resource_exhaust*))
        )
}

rule UAC0099_VBS_Double_Extension_Dropper
{
    meta:
        description = "Detects VBScript dropper files using double file extension technique as used in UAC-0099 phishing campaigns to deliver LUNCHPOKE and BURNYBEAR"
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $vbs_header1 = "CreateObject" ascii nocase
        $vbs_header2 = "WScript" ascii nocase
        $evernote = "Evernote" ascii wide nocase
        $notepad = "notepad++" ascii wide nocase
        $npp = "NppExport" ascii wide
        $rar_ref = "updater.rar" ascii wide nocase
        $download1 = "XMLHTTP" ascii nocase
        $download2 = "ADODB.Stream" ascii nocase
        $shell1 = "WScript.Shell" ascii nocase

    condition:
        filesize < 500KB and
        1 of ($vbs_header*) and
        (
            ($evernote and ($notepad or $npp)) or
            ($download1 and $shell1 and ($evernote or $rar_ref)) or
            ($download2 and ($notepad or $npp))
        )
}
