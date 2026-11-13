/*
    YARA Rule: SCKit Toolkit Component Detection
    Author: Actioner
    Date: 2026-11-13
    Description: Detects SCKit worm toolkit components targeting ScreenConnect MSP environments.
                 Covers PowerShell scripts, batch files, and configuration artifacts.
    References:
        - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
        - https://blackpointcyber.com/blog/screenconnect-attack-sckit/
*/

rule SCKit_RelayTrap_Source
{
    meta:
        description = "Detects SCKit RelayTrap C# source code used to replace legitimate ScreenConnect Guest process"
        author = "Actioner"
        date = "2026-11-13"
        hash = "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4"
        severity = "critical"

    strings:
        $class1 = "RelayTrap" ascii wide
        $class2 = "TrapWatch" ascii wide
        $func1 = "TransferFilesMessage" ascii wide
        $func2 = "FileAction.Run" ascii wide
        $func3 = "canBeElevated" ascii wide
        $sc1 = "ScreenConnect.Client" ascii wide
        $sc2 = "ScreenConnect.Core" ascii wide
        $path1 = "ProgramData\\RelayTrap" ascii wide nocase

    condition:
        filesize < 500KB and
        (
            ($class1 and $class2 and any of ($sc*)) or
            ($class1 and $func1 and $func2) or
            ($path1 and $class1 and any of ($func*))
        )
}

rule SCKit_TrapWatch_Script
{
    meta:
        description = "Detects SCKit TrapWatch PowerShell script that monitors and replaces ScreenConnect services"
        author = "Actioner"
        date = "2026-11-13"
        hash = "d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a"
        severity = "critical"

    strings:
        $s1 = "TrapWatch" ascii wide
        $s2 = "RelayTrap" ascii wide
        $s3 = "trapbins" ascii wide
        $s4 = "LabTrapMonitorOnly" ascii wide
        $s5 = "PanelSessionWaitSec" ascii wide
        $s6 = "HostSessionWaitSec" ascii wide

    condition:
        filesize < 200KB and 4 of them
}

rule SCKit_PanelLateral_Script
{
    meta:
        description = "Detects SCKit Panel-Lateral PowerShell scripts used for technician session cookie theft and lateral movement"
        author = "Actioner"
        date = "2026-11-13"
        hash1 = "94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11"
        hash2 = "7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec"
        severity = "critical"

    strings:
        $s1 = "Panel-Lateral" ascii wide
        $s2 = ".ASPXAUTH" ascii wide nocase
        $s3 = "PageService.ashx" ascii wide
        $s4 = "GetAccessToken" ascii wide
        $s5 = "GetLiveData" ascii wide
        $s6 = "AddSessionEvents" ascii wide
        $s7 = "QueuedCommand" ascii wide
        $s8 = "LabConfig" ascii wide

    condition:
        filesize < 500KB and
        (
            ($s1 and $s2 and any of ($s3, $s4, $s5, $s6, $s7, $s8)) or
            ($s2 and 3 of ($s3, $s4, $s5, $s6, $s7, $s8))
        )
}

rule SCKit_LabContext_Config
{
    meta:
        description = "Detects SCKit lab-context.json configuration file containing attacker panel and rogue client IDs"
        author = "Actioner"
        date = "2026-11-13"
        hash = "0bd84c776dc01f784a617e73fc77b269f847fc4a062ffd489e4692869724bf08"
        severity = "critical"

    strings:
        $id1 = "2588ef5c15954b10" ascii wide
        $id2 = "ed630cc2c873b091" ascii wide
        $domain1 = "payproofkit.com" ascii wide
        $domain2 = "mo7sen.dev" ascii wide
        $domain3 = "soxnewwork.homedns.org" ascii wide
        $domain4 = "newnewnew.gotdns.org" ascii wide
        $ip1 = "185.99.255.28" ascii wide

    condition:
        filesize < 100KB and 3 of them
}

rule SCKit_ToolboxRelayUploader
{
    meta:
        description = "Detects SCKit ToolboxRelayUploader.exe .NET binary used to upload malicious payloads to ScreenConnect Shared Toolbox"
        author = "Actioner"
        date = "2026-11-13"
        hash = "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af"
        severity = "critical"

    strings:
        $s1 = "ToolboxRelayUploader" ascii wide
        $s2 = "SharedToolbox" ascii wide
        $s3 = "--delete" ascii wide
        $net1 = "_CorExeMain" ascii
        $net2 = "mscoree.dll" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        any of ($net*) and
        ($s1 or ($s2 and $s3))
}

rule SCKit_Stage0Loader
{
    meta:
        description = "Detects SCKit Stage0Loader PowerShell script that fetches encrypted payloads from attacker staging server"
        author = "Actioner"
        date = "2026-11-13"
        hash = "81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781"
        severity = "critical"

    strings:
        $url1 = "EadF.php" ascii wide
        $url2 = "mo7sen.dev" ascii wide
        $hdr1 = "X-Lab-Half" ascii wide
        $hdr2 = "X-Lab-Salt" ascii wide
        $crypto1 = "PBKDF2" ascii wide nocase
        $crypto2 = "AES" ascii wide
        $crypto3 = "MachineGuid" ascii wide

    condition:
        filesize < 200KB and
        (
            ($url1 and any of ($hdr*)) or
            ($url2 and any of ($hdr*)) or
            ($url1 and $url2 and any of ($crypto*))
        )
}

rule SCKit_Dropper_Batch
{
    meta:
        description = "Detects SCKit batch dropper scripts including sckit-run.bat and Run-Lateral-Full.bat"
        author = "Actioner"
        date = "2026-11-13"
        hash1 = "43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95"
        hash2 = "50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61"
        severity = "critical"

    strings:
        $sckit1 = "sckit-decoder" ascii wide nocase
        $sckit2 = "sckit-loader" ascii wide nocase
        $sckit3 = "sckit-run" ascii wide nocase
        $sckit4 = "Run-Lateral-Full" ascii wide nocase
        $mode1 = "-Mode full" ascii wide nocase
        $mode2 = "-Mode cleanup" ascii wide nocase

    condition:
        filesize < 100KB and
        (
            any of ($sckit*) and 1 of ($mode*)
        )
}

/*
    YARA Rule: SCKit Network and Hash-Based Indicators
    Author: Actioner
    Date: 2026-11-13
    Description: Detects SCKit artifacts by SHA-256 hash and network indicator presence in files.
    References:
        - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
        - https://blackpointcyber.com/blog/screenconnect-attack-sckit/
*/

rule SCKit_Installer_MSI
{
    meta:
        description = "Detects the SCKit rogue ScreenConnect MSI installer by hash"
        author = "Actioner"
        date = "2026-11-13"
        hash = "d85315bd7602b6f5c13dc0eada2c9cba0892c7cd3b1eb7dacb1bffdd536ceb21"
        severity = "critical"

    strings:
        $msi_magic = {D0 CF 11 E0 A1 B1 1A E1}
        $sc_str1 = "ScreenConnect" ascii wide
        $relay1 = "soxnewwork.homedns.org" ascii wide
        $relay2 = "newnewnew.gotdns.org" ascii wide
        $relay3 = "185.99.255.28" ascii wide

    condition:
        $msi_magic at 0 and
        $sc_str1 and
        any of ($relay*)
}

rule SCKit_SilentForceInstall
{
    meta:
        description = "Detects SCKit SilentForceInstall-WithUninstall.ps1 that installs rogue ScreenConnect Access clients"
        author = "Actioner"
        date = "2026-11-13"
        hash = "a1937467fd862916f89342cdd61f55c4bc405fb35b6e1379e27cfbfdba77dcdc"
        severity = "critical"

    strings:
        $s1 = "SilentForceInstall" ascii wide nocase
        $s2 = "WithUninstall" ascii wide nocase
        $s3 = "ScreenConnect.ClientSetup" ascii wide
        $s4 = "Exploited" ascii wide
        $s5 = "Addmin" ascii wide

    condition:
        filesize < 200KB and 3 of them
}
