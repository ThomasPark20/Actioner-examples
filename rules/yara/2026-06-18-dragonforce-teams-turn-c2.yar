rule Malware_DragonForce_Backdoor_Turn
{
    meta:
        description = "Detects Backdoor.Turn Go-based RAT used by DragonForce ransomware operators, which abuses Microsoft Teams TURN relay infrastructure for C2"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6"
        hash = "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $go1 = "runtime.main" ascii
        $go2 = "main.main" ascii

        $turn1 = "TURN" ascii fullword
        $turn2 = "STUN" ascii fullword
        $turn3 = "visitor" ascii
        $turn4 = "relay" ascii
        $turn5 = "teams" ascii nocase

        $quic1 = "quic-go" ascii
        $quic2 = "quic.Config" ascii
        $quic3 = "QUIC" ascii fullword

        $c2_1 = "projetosmecanicos.com.br" ascii
        $c2_2 = "socialbizsolutions.com" ascii
        $c2_3 = "professionalhomebasedbusiness.com" ascii
        $c2_4 = "safefire.jo" ascii
        $c2_5 = "glanz-gmbh.de" ascii
        $c2_6 = "turnkeyaiagents.com" ascii
        $c2_7 = "comunidadesparentais.com.br" ascii
        $c2_8 = "mysimerp.net" ascii

        $cap1 = "CreateProcess" ascii
        $cap2 = "ldap" ascii nocase
        $cap3 = "NetScan" ascii
        $cap4 = "credential" ascii nocase

    condition:
        filesize < 30MB and
        (
            (uint16(0) == 0x5A4D and 3 of ($c2_*)) or
            (
                all of ($go*) and
                2 of ($turn*) and
                1 of ($quic*) and
                1 of ($cap*)
            )
        )
}

rule Malware_DragonForce_Backdoor_Turn_Downloader
{
    meta:
        description = "Detects the vboxrt.dll downloader DLL used in DragonForce Backdoor.Turn sideloading attacks"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b"
        hash = "d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e"
        tlp = "WHITE"
        severity = "high"

    strings:
        $s1 = "vboxrt.dll" ascii wide nocase
        $s2 = "VirtualBox" ascii wide
        $s3 = "DbgView" ascii wide

        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "InternetOpenUrl" ascii
        $dl3 = "HttpSendRequest" ascii
        $dl4 = "WinHttpOpen" ascii

        $c2_1 = "projetosmecanicos.com.br" ascii
        $c2_2 = "socialbizsolutions.com" ascii
        $c2_3 = "professionalhomebasedbusiness.com" ascii
        $c2_4 = "turnkeyaiagents.com" ascii
        $c2_5 = "mysimerp.net" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($c2_*) and 1 of ($s*)) or
            (1 of ($s*) and 2 of ($dl*) and 1 of ($c2_*))
        )
}

rule Malware_DragonForce_Ransomware
{
    meta:
        description = "Detects DragonForce ransomware binary based on known hash"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ransom1 = "DragonForce" ascii wide nocase
        $ransom2 = ".dragonforce" ascii wide
        $encrypt1 = "CryptEncrypt" ascii
        $encrypt2 = "BCryptEncrypt" ascii
        $encrypt3 = "CryptGenRandom" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $ransom1 and $ransom2 and
        1 of ($encrypt*)
}
