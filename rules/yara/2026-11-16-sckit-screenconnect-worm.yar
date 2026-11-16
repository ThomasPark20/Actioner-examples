/*
    SCKit ScreenConnect Worm - YARA Detection Rules
    4 rules: toolkit strings, ToolboxRelayUploader, RelayTrap source, dropper batch
    Generated 2026-11-16
    References:
      - https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
      - https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
*/

rule SCKit_Toolkit_Strings
{
    meta:
        description = "Detects SCKit worm toolkit files by characteristic strings"
        author = "Actioner CTI"
        date = "2026-11-16"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash1 = "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af"

    strings:
        $s1 = "RelayTrap" ascii wide
        $s2 = "TrapWatch" ascii wide
        $s3 = "SCKitBundle" ascii wide
        $s4 = "ToolboxRelayUploader" ascii wide
        $s5 = "Panel-Lateral" ascii wide
        $s6 = "Stage0Loader" ascii wide
        $s7 = "EadF.php" ascii wide
        $s8 = "sckit-decoder" ascii wide
        $s9 = "sckit-loader" ascii wide
        $s10 = "RelayTrapLiteAlert" ascii wide
        $s11 = "PollSeconds" ascii wide
        $s12 = "NoReArm" ascii wide

        $d1 = "ns.mo7sen.dev" ascii wide
        $d2 = "payproofkit.com" ascii wide
        $d3 = "cdn007-digitaldownloads.com" ascii wide

        $c1 = "c=Exploited" ascii wide
        $c2 = "RELAY-TRAP-PROOF" ascii wide

    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or 2 of ($d*) or (1 of ($d*) and 1 of ($s*)) or (1 of ($c*) and 1 of ($s*)))
        or
        not uint16(0) == 0x5a4d and (2 of ($s*) or 1 of ($d*) or 1 of ($c*))
}

rule SCKit_ToolboxRelayUploader
{
    meta:
        description = "Detects the SCKit ToolboxRelayUploader .NET executable by hash"
        author = "Actioner CTI"
        date = "2026-11-16"
        reference = "https://www.huntress.com/blog/sckit-worm-rogue-screenconnect"
        hash = "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af"

    strings:
        $dotnet = "mscoree.dll" ascii
        $name = "ToolboxRelayUploader" ascii wide
        $shared = "SharedToolbox" ascii wide

    condition:
        uint16(0) == 0x5a4d and $dotnet and $name and $shared
}

rule SCKit_RelayTrap_Source
{
    meta:
        description = "Detects SCKit RelayTrap C# source code"
        author = "Actioner CTI"
        date = "2026-11-16"
        reference = "https://www.huntress.com/blog/sckit-worm-rogue-screenconnect"
        hash = "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4"

    strings:
        $cs1 = "RelayTrap" ascii
        $cs2 = "TrapWatch" ascii
        $cs3 = "ScreenConnect" ascii
        $cs4 = "ClientService" ascii

    condition:
        all of them and filesize < 500KB
}

rule SCKit_Dropper_Batch
{
    meta:
        description = "Detects SCKit dropper batch files"
        author = "Actioner CTI"
        date = "2026-11-16"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"

    strings:
        $b1 = "sckit-run" ascii nocase
        $b2 = "sckit-decoder" ascii nocase
        $b3 = "Run-Lateral-Full" ascii nocase
        $b4 = "TRAP-PROOF" ascii nocase
        $b5 = "Stop-LabTrap" ascii nocase
        $b6 = "RelayTrap" ascii nocase
        $b7 = "EadF.php" ascii nocase

    condition:
        2 of them and filesize < 100KB
}
