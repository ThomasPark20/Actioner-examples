/*
 * UAT-11795 Starland RAT & WLDR C2 Campaign - YARA Detection Rules
 * Author: Actioner
 * Date: 2026-07-18
 * Reference: https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
 * Total: 3 rules
 */

rule Malware_Starland_RAT_Loader
{
    meta:
        description = "Detects Starland RAT Python loader via XOR key 0xC6 decryption pattern and anti-analysis sandbox hostnames"
        author = "Actioner"
        date = "2026-07-18"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "critical"
        confidence = "high"

    strings:
        $sandbox1 = "WDAGUtilityAccount" ascii wide
        $sandbox2 = "Cuckoo" ascii wide
        $sandbox3 = "Any.Run" ascii wide
        $sandbox4 = "Joe Sandbox" ascii wide
        $sandbox5 = "Hybrid Analysis" ascii wide

        $xor_key_recon = "helo1" ascii

        $cmd1 = "shellexecute" ascii wide
        $cmd2 = "download" ascii wide

        $recon1 = "Win32_ComputerSystemProduct" ascii wide
        $recon2 = "AntiVirusProduct" ascii wide
        $recon3 = "nltest /dclist" ascii wide

        $ua = "Chrome/138.0.0.0 Safari/537.36" ascii wide

    condition:
        filesize < 10MB and
        (
            (3 of ($sandbox*) and $xor_key_recon) or
            (2 of ($sandbox*) and 2 of ($recon*) and $ua) or
            ($xor_key_recon and 2 of ($recon*) and 1 of ($cmd*))
        )
}

rule Malware_WLDR_C2_Implant
{
    meta:
        description = "Detects the WLDR C2 PowerShell implant via unique mutex, hardcoded password, and protocol markers"
        author = "Actioner"
        date = "2026-07-18"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "critical"
        confidence = "high"

    strings:
        $mutex = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $password = "odg5t8mvssvh" ascii wide
        $protocol = "WSv1" ascii wide
        $aes = "AES" ascii wide
        $hmac = "HMACSHA256" ascii wide

    condition:
        filesize < 5MB and
        (
            $mutex or
            ($password and $protocol) or
            ($password and $aes and $hmac)
        )
}

rule Malware_Starland_Trojanized_Installer
{
    meta:
        description = "Detects trojanized NSIS installers used by UAT-11795 to deploy Starland RAT via pythonw.exe LICENSE.txt execution"
        author = "Actioner"
        date = "2026-07-18"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"
        confidence = "medium"

    strings:
        $nsis = "Nullsoft" ascii wide
        $pythonw = "pythonw.exe" ascii wide
        $license = "LICENSE.txt" ascii wide
        $task = "PythonLauncher-" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 200MB and
        $nsis and $pythonw and $license and
        $task
}
