rule SupplyChain_cPGuard_Malicious_Update_Script
{
    meta:
        description = "Detects malicious cPGuard update scripts from the November 2026 supply chain attack based on distinctive file paths, collection patterns, and script naming"
        author = "Actioner"
        date = "2026-11-09"
        reference = "https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html"
        hash = "2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38"
        hash2 = "ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a"
        hash3 = "d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26"
        hash4 = "6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $staging_dir = "/var/tmp/.cpg91511" ascii
        $backdoor_path = "/var/tmp/.cpg91511_sh" ascii
        $loot_archive = "loot.tgz" ascii
        $cron_persist = "/etc/cron.d/i93677" ascii
        $cron_workdir = "/var/tmp/.i93677" ascii
        $shadow_read = "/etc/shadow" ascii
        $ssh_read = "/root/.ssh" ascii
        $mycnf_read = "/root/.my.cnf" ascii
        $script_name = "cpguard-v58812-i91511" ascii

    condition:
        filesize < 1MB and
        $script_name and
        (
            ($staging_dir and $loot_archive) or
            ($backdoor_path and $cron_persist) or
            (3 of ($shadow_read, $ssh_read, $mycnf_read, $staging_dir, $cron_workdir))
        )
}

rule SupplyChain_cPGuard_Setuid_Backdoor
{
    meta:
        description = "Detects the setuid-root shell backdoor dropped by the cPGuard supply chain attack at /var/tmp/.cpg91511_sh"
        author = "Actioner"
        date = "2026-11-09"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $path_marker = ".cpg91511_sh" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $path_marker
}

rule SupplyChain_cPGuard_GoImplant_Infra
{
    meta:
        description = "Detects Go implant artifacts found on OPSSHIELD infrastructure during the cPGuard supply chain attack. The implant masqueraded as system processes."
        author = "Actioner"
        date = "2026-11-09"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "high"
        tlp = "WHITE"

    strings:
        $fake_proc1 = "[slub_flushwq]" ascii
        $fake_proc2 = "[rcu_gp]" ascii
        $implant_name1 = "pythno3" ascii
        $implant_name2 = "netstat.cfg" ascii
        $implant_name3 = "system.mark" ascii
        $implant_name4 = "libgdi.so.0.8.2" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 50MB and
        $implant_name1 and
        (
            2 of ($fake_proc*) or
            2 of ($implant_name*)
        )
}
