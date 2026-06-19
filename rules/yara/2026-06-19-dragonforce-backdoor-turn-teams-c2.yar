/*
 * DragonForce Backdoor.Turn Campaign - YARA Detection Rules
 * Report: summaries/2026-06-19-dragonforce-backdoor-turn-teams-c2.md
 * Generated: 2026-06-19
 * Total: 3 rules (1 IOC high, 1 behavioral medium, 1 hash high)
 */

import "hash"

rule Malware_DragonForce_Backdoor_Turn_IOC : backdoor rat
{
    meta:
        description = "Detects Backdoor.Turn by known C2 domains and IP addresses used by DragonForce ransomware operators"
        author = "Actioner"
        date = "2026-06-19"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6"
        hash2 = "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // C2 domains
        $c2_1 = "projetosmecanicos.com.br" ascii
        $c2_2 = "socialbizsolutions.com" ascii
        $c2_3 = "professionalhomebasedbusiness.com" ascii
        $c2_4 = "safefire.jo" ascii
        $c2_5 = "glanz-gmbh.de" ascii
        $c2_6 = "turnkeyaiagents.com" ascii
        $c2_7 = "comunidadesparentais.com.br" ascii
        $c2_8 = "mysimerp.net" ascii

        // C2 IP
        $c2_ip = "62.164.177.25" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        any of ($c2_*)
}

rule Malware_DragonForce_Backdoor_Turn_Behavioral : backdoor rat
{
    meta:
        description = "Detects Backdoor.Turn Go-based RAT by behavioral indicators: Go binary with QUIC library, Teams/Skype TURN relay token acquisition, and LDAP/scanning capabilities"
        author = "Actioner"
        date = "2026-06-19"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        hash = "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6"
        hash2 = "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c"
        tlp = "WHITE"
        severity = "high"

    strings:
        // Go build artifact strings
        $go1 = "runtime.goexit" ascii
        $go2 = "runtime.main" ascii

        // QUIC library indicators (more specific than generic "QUIC")
        $quic1 = "quic-go" ascii

        // Microsoft Teams / Skype TURN relay specific strings
        $ms_turn1 = "turn.teams.microsoft.com" ascii wide
        $ms_turn2 = "api.flightproxy.skype.com" ascii wide
        $ms_turn3 = "turn3.teams.microsoft.com" ascii wide
        $ms_turn4 = "relay.teams.microsoft.com" ascii wide
        $ms_turn5 = "TURN_RELAY" ascii
        $ms_turn6 = "visitor_token" ascii
        $ms_turn7 = "anonymousToken" ascii

        // RAT capability strings (more specific)
        $cap1 = "ldap://" ascii nocase
        $cap2 = "netscan" ascii nocase
        $cap3 = "browsercredentials" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        all of ($go*) and
        $quic1 and
        2 of ($ms_turn*) and
        1 of ($cap*)
}

rule Malware_DragonForce_Backdoor_Turn_Hash : backdoor rat
{
    meta:
        description = "Detects known Backdoor.Turn samples by SHA256 hash match"
        author = "Actioner"
        date = "2026-06-19"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $hex_marker = { 4D 5A }

    condition:
        $hex_marker at 0 and
        filesize < 20MB and
        (
            hash.sha256(0, filesize) == "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6" or
            hash.sha256(0, filesize) == "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c" or
            hash.sha256(0, filesize) == "ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0" or
            hash.sha256(0, filesize) == "82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b"
        )
}
