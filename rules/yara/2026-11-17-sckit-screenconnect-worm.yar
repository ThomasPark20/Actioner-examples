/*
 * SCKit ScreenConnect Worm Campaign - YARA Rules
 * Author: Actioner
 * Date: 2026-11-17
 * Reference: https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
 */

rule SCKit_Toolkit_Strings
{
    meta:
        description = "Detects SCKit toolkit components via distinctive strings found in PowerShell scripts, batch files, and C# source"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        severity = "high"

    strings:
        $s1 = "SCKitBundle" ascii wide
        $s2 = "RelayTrap" ascii wide
        $s3 = "TrapWatch" ascii wide
        $s4 = "ToolboxRelayUploader" ascii wide
        $s5 = "Panel-Lateral" ascii wide
        $s6 = "Stage0Loader" ascii wide
        $s7 = "Lite-Alert" ascii wide
        $s8 = "RelayTrapLiteAlert" ascii wide
        $s9 = "TRAP-PROOF" ascii wide
        $s10 = "EadF.php" ascii wide
        $s11 = "X-Lab-Half" ascii wide
        $s12 = "X-Lab-Salt" ascii wide
        $s13 = "lab-context.json" ascii wide
        $s14 = "-PollSeconds" ascii wide
        $s15 = "c=Exploited" ascii wide

    condition:
        filesize < 5MB and 3 of them
}

rule SCKit_RelayTrap_CS_Source
{
    meta:
        description = "Detects RelayTrap.cs source file used in the SCKit campaign worm component"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash = "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4"
        severity = "high"

    strings:
        $s1 = "RelayTrap" ascii
        $s2 = ".ASPXAUTH" ascii
        $s3 = "network.mojom.NetworkService" ascii
        $s4 = "VirtualQueryEx" ascii
        $s5 = "ReadProcessMemory" ascii
        $s6 = "OpenProcess" ascii

    condition:
        filesize < 2MB and 4 of them
}
