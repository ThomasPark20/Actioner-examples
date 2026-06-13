rule Malware_AsyncRAT_FakeAIGuide_LNK : asyncrat lnk
{
    meta:
        description = "Detects malicious LNK files from the AsyncRAT fake AI guide campaign using findstr to extract payloads from PDF containers"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat"
        severity = "high"

    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 }
        $s1 = "findstr" ascii wide nocase
        $s2 = "3th.pdf" ascii wide
        $s3 = "4th.pdf" ascii wide
        $s4 = "cmd.exe" ascii wide nocase
        $s5 = "PGP PRIVATE KEY BLOCK" ascii wide

    condition:
        $lnk_header at 0 and
        filesize < 50KB and
        (($s1 and ($s2 or $s3)) or
        ($s4 and $s5))
}

rule Malware_AsyncRAT_FakeAIGuide_AHK_Loader : asyncrat autohotkey
{
    meta:
        description = "Detects AutoHotkey scripts used as loaders in the AsyncRAT fake AI guide campaign with Realtek masquerading"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat"
        severity = "high"

    strings:
        $ahk1 = "DllCall" ascii nocase
        $ahk2 = "VirtualAlloc" ascii nocase
        $ahk3 = "NumPut" ascii nocase
        $ahk4 = "CreateThread" ascii nocase
        $realtek1 = "RealtekAudio" ascii wide nocase
        $realtek2 = "RtkNGUI" ascii wide nocase
        $realtek3 = "RtkDiagService" ascii wide nocase
        $realtek4 = "RtkCplApp" ascii wide nocase

    condition:
        filesize < 5MB and
        (2 of ($ahk*) and 1 of ($realtek*))
}

rule Malware_AsyncRAT_FakeAIGuide_PS1_Stager : asyncrat powershell
{
    meta:
        description = "Detects PowerShell stager scripts from the AsyncRAT campaign with AES-CBC decryption and Defender exclusion artifacts"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat"
        hash = "7d6ee3c6ff8f70b1817aaec82aff1d2babe0b62cafef3975262644743afc0cb8"
        severity = "critical"

    strings:
        $ps1 = "Add-MpPreference" ascii nocase
        $ps2 = "ExclusionPath" ascii nocase
        $ps3 = "AesCryptoServiceProvider" ascii nocase
        $ps4 = "RijndaelManaged" ascii nocase
        $ps5 = "PBKDF2" ascii nocase
        $c2_1 = "shampobiskworld" ascii nocase
        $c2_2 = "shampoolagtto" ascii nocase
        $c2_3 = "shamppocosmaticso" ascii nocase
        $cn1 = { E6 B5 8B E8 AF 95 E8 B7 AF E5 BE 84 }
        $cn2 = { E8 BF 9E E6 8E A5 E8 B7 AF E5 BE 84 }
        $xor_key = "Realtek2025" ascii wide

    condition:
        filesize < 2MB and
        (
            (2 of ($ps*)) or
            (1 of ($c2*)) or
            ($cn1 and $cn2) or
            ($xor_key and 1 of ($ps*))
        )
}

rule Malware_AsyncRAT_ClayClient_Payload : asyncrat clay_client
{
    meta:
        description = "Detects the clay_Client .NET RAT payload deployed alongside AsyncRAT in the fake AI guide campaign"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.fortinet.com/blog/threat-research/threat-actors-weaponize-ai-hype-to-deliver-asyncrat"
        severity = "critical"

    strings:
        $mutex = "IDG5FUAM3PSONBSInGIGSWSD" ascii wide
        $cap1 = "ClientShutdown" ascii
        $cap2 = "ClientDelete" ascii
        $cap3 = "ClientUpdate" ascii
        $cap4 = "RemoteDesktopOpen" ascii
        $cap5 = "RemoteDesktopSend" ascii
        $cap6 = "mousemove" ascii
        $cap7 = "RunPE" ascii
        $cap8 = "Reflection" ascii
        $myth1 = { E4 B9 9D E5 A4 A9 E7 8E 84 E5 A5 B3 }
        $myth2 = { E4 B9 BE E5 9D A4 E8 A2 8B }
        $myth3 = { E8 B5 B7 E6 AD BB E5 9B 9E E7 94 9F }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $mutex or
            (4 of ($cap*)) or
            (2 of ($myth*))
        )
}
