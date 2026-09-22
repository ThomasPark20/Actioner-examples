rule Exploit_Cisco_FMC_CVE_2026_20079_WebShell
{
    meta:
        description = "Detects JSP web shell (home.jsp) and cmd.jar command executor deployed by UAT-12197 following CVE-2026-20079 exploitation on Cisco FMC"
        author = "Actioner"
        date = "2026-09-11"
        reference = "https://blog.talosintelligence.com/fmc-ongoing-exploitation/"
        hash1 = "b037f45e02a289325a1a5eb0d4db6a9fce9954fd0fdfd07162cb4eb2acbef77d"
        hash2 = "db491181ece3f319de6567ab6f6daa90c6879911cd890155e6b7d8cc7a1a8c8e"
        severity = "critical"

    strings:
        $jsp_param = "F6C1F0E7" ascii wide
        $cmd_jar = "cmd.jar" ascii
        $omniquery = "OmniQuery.pl" ascii
        $auth_data = "auth_data" ascii
        $select_users = "SELECT name" ascii

    condition:
        (uint16(0) == 0x4B50 and ($cmd_jar and $omniquery)) or
        ($jsp_param and filesize < 100KB) or
        (3 of ($cmd_jar, $omniquery, $auth_data, $select_users) and filesize < 10MB)
}
rule Malware_CyclopsBlink_Cisco_FMC
{
    meta:
        description = "Detects Cyclops Blink modular ELF implant deployed by UAT-11823 (Sandworm) on Cisco FMC following CVE-2026-20079 exploitation"
        author = "Actioner"
        date = "2026-09-11"
        reference = "https://blog.talosintelligence.com/fmc-ongoing-exploitation/"
        hash = "6f98add5d1a7729192b6ad8491d85c505c64836f7881742d6b93bd8e3d2fe461"
        severity = "critical"

    strings:
        $initd1 = "/etc/init.d/" ascii
        $doh1 = "dns-query" ascii
        $doh2 = "application/dns-message" ascii
        $nc_shell = "mkfifo /tmp/f" ascii
        $nc_cmd = "/bin/sh -i" ascii

    condition:
        uint32(0) == 0x464C457F and (
            ($initd1 and ($doh1 or $doh2)) or
            ($nc_shell and $nc_cmd) or
            (3 of ($initd1, $doh1, $doh2, $nc_shell, $nc_cmd))
        )
}
