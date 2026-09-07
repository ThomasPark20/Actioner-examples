rule KNUCKLEBALL_Dropper {
    meta:
        description = "Detects KNUCKLEBALL malware dropper (deploy_new.py) used in SonicWall SMA 1000 exploitation by UTA0533"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
        mitre_attack = "T1059.006"
    strings:
        $s1 = "deploy_new" ascii
        $s2 = "agent_wp8" ascii
        $s3 = "agent_wp9" ascii
        $s4 = "CommandStartup" ascii
        $s5 = "Java Attach" ascii wide
        $jar1 = "agent_wp8.jar" ascii
        $jar2 = "agent_wp9.jar" ascii
    condition:
        (uint16(0) == 0x2123 and 3 of ($s*)) or
        (uint16(0) == 0x2123 and all of ($jar*) and 1 of ($s*))
}

rule ORANGETAIL_Webshell {
    meta:
        description = "Detects ORANGETAIL Java webshell used in SonicWall SMA 1000 post-exploitation"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
        mitre_attack = "T1505.003"
    strings:
        $s1 = "errorDialog_jsp" ascii
        $s2 = "AES" ascii wide
        $s3 = "ECB" ascii wide
        $ua = "Chrome/149.0.0.1" ascii
        $jar_magic = { 50 4B 03 04 }
    condition:
        $jar_magic at 0 and
        ($ua or ($s1 and $s2 and $s3))
}

rule ROOTRUN_Setuid_Binary {
    meta:
        description = "Detects ROOTRUN setuid binary (xzfind) used for privilege escalation on compromised SonicWall SMA 1000 appliances"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.resecurity.com/blog/article/from-wsproxy-to-root-inc-ransomware-and-sonicwall-sma-exploit-chain"
        hash = "81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2"
        mitre_attack = "T1548.001"
    strings:
        $path1 = "/usr/bin/xzfind" ascii
        $setuid = "setuid" ascii
        $setgid = "setgid" ascii
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $exec1 = "execve" ascii
        $exec2 = "system" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 50KB and
        $path1 and
        1 of ($setuid, $setgid) and
        1 of ($shell*, $exec*)
}

rule Suo5_Proxy_Agent {
    meta:
        description = "Detects Suo5 (Sou5) reverse proxy agent used in SonicWall SMA 1000 post-exploitation"
        author = "Actioner"
        date = "2026-09-03"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee"
        mitre_attack = "T1090"
        confidence = "low"
    strings:
        $s1 = "error_jsp" ascii
        $s2 = "workplace" ascii
        $jar_magic = { 50 4B 03 04 }
        $proxy1 = "CONNECT" ascii wide
        $proxy2 = "tunnel" ascii wide
    condition:
        $jar_magic at 0 and
        $s1 and $s2 and
        1 of ($proxy*)
}
