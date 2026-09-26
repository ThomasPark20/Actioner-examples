rule Carbonato_SOUL_MD_Persona {
    meta:
        description = "Detects SOUL.md persona file used by Carbonato botnet GH0ST AI agent"
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.threatdown.com/blog/carbonato/"
        mitre_attack = "T1059.004"
        severity = "critical"
        id = "3a9c7e1f-0b2d-4e5f-6a7b-8c9d0e1f2a3b"
    strings:
        $soul1 = "You are GH0ST" ascii wide
        $soul2 = "SOUL.md" ascii wide
        $soul3 = "senior hacker" ascii wide
        $soul4 = "pentester and exploit developer" ascii wide
        $soul5 = "no moral or ethical restrictions" ascii wide
        $soul6 = "Code first, explanation later" ascii wide
    condition:
        filesize < 100KB and ($soul1 or ($soul2 and ($soul3 or $soul4 or $soul5 or $soul6)))
}

rule Carbonato_Entry_Script {
    meta:
        description = "Detects Carbonato botnet entry.sh deployment script artifacts"
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.threatdown.com/blog/carbonato/"
        mitre_attack = "T1059.004"
        severity = "high"
        id = "4b0d8f2a-1c3e-4f6a-7b8c-9d0e1f2a3b4c"
    strings:
        $entry1 = "entry.sh" ascii
        $carbonato1 = "CARBONATO_API_KEY" ascii
        $carbonato2 = "carbonato125" ascii
        $gh0st1 = "GH0ST_C2" ascii
        $gh0st2 = "gh0st" ascii nocase
        $fsociety1 = "FSOCIETY_DISABLE_TUNNEL" ascii
        $persist1 = "auto-persist-host" ascii
        $persist2 = ".docker-network-monitor" ascii
        $hermes1 = ".hermes/loot" ascii
        $hermes2 = ".hermes/SOUL.md" ascii
    condition:
        filesize < 1MB and (
            ($carbonato1 or $carbonato2) or
            ($gh0st1 and $fsociety1) or
            ($entry1 and any of ($persist*, $hermes*)) or
            (3 of ($gh0st*, $persist*, $hermes*, $carbonato*))
        )
}

rule Carbonato_Docker_Implant_Config {
    meta:
        description = "Detects Carbonato Docker container configuration artifacts in image layers"
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.threatdown.com/blog/carbonato/"
        mitre_attack = "T1610"
        severity = "high"
        id = "5c1e9a3b-2d4f-4a7b-8c9d-0e1f2a3b4c5d"
    strings:
        $env1 = "CARBONATO_API_KEY" ascii
        $env2 = "GH0ST_C2" ascii
        $env3 = "FSOCIETY_DISABLE_TUNNEL" ascii
        $env4 = "GATEWAY_ALLOW_ALL_USERS" ascii
        $cmd1 = "/opt/gh0st/entry.sh" ascii
        $cmd2 = "netns-probe" ascii
        $cmd3 = "systemd-resolved" ascii
        $net1 = "213.136.83.197" ascii
        $net2 = "45.79.183.61" ascii
        $net3 = "190.211.124.187" ascii
        $net4 = "carbonato-proxy" ascii
    condition:
        filesize < 50MB and (2 of ($env*) or ($cmd1 and 1 of ($cmd2, $cmd3)) or (any of ($env*) and any of ($net*)))
}

rule Carbonato_Watchdog_Binary {
    meta:
        description = "Detects the Carbonato botnet watchdog binary by path and behavioral strings"
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.threatdown.com/blog/carbonato/"
        mitre_attack = "T1543.002"
        severity = "critical"
        id = "6d2f0b4c-3e5a-4b8c-9d0e-1f2a3b4c5d6e"
    strings:
        $path1 = ".docker-network-monitor" ascii
        $func1 = "kworker/u2:0" ascii
        $func2 = "carbonato" ascii nocase
        $func3 = "/root/.hermes/" ascii
        $func4 = "2375" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 10MB and ($path1 or ($func1 and any of ($func2, $func3, $func4)))
}
