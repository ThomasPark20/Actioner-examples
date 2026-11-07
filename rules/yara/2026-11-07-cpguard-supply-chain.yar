/*
    YARA Rules for cPGuard Supply Chain Attack (November 2026)
    Detects malicious update scripts and associated backdoor artifacts.

    References:
        - https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html
        - https://opsshield.com/notice/cpguard-update-channel-compromise.html
        - https://opsshield.com/notice/security-incident-disclosure-servermanage.html

    Author: Actioner CTI
    Date: 2026-11-07
*/

rule CPGuard_Malicious_Update_Script
{
    meta:
        description = "Detects the malicious cPGuard update scripts distributed via the hijacked update channel"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "critical"
        hash1 = "2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38"
        hash2 = "ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a"
        hash3 = "d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26"
        hash4 = "6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77"

    strings:
        $script_name1 = "cpguard-v58812-i91511" ascii
        $script_name2 = "cpguard-v58812-i91511b" ascii
        $script_name3 = "cpguard-v58812-i91511c" ascii
        $script_name4 = "cpguard-v58812-i91511d" ascii

        $backdoor_path = "/var/tmp/.cpg91511_sh" ascii
        $staging_dir = "/var/tmp/.cpg91511" ascii
        $cron_path = "/etc/cron.d/i93677" ascii
        $task_dir = "/var/tmp/.i93677" ascii
        $loot_archive = "loot.tgz" ascii

        $harvest_shadow = "/etc/shadow" ascii
        $harvest_ssh = "/root/.ssh" ascii
        $harvest_mysql = "/root/.my.cnf" ascii
        $harvest_s3 = "/root/.s3cfg" ascii

        $probe1 = "i90248_probe" ascii
        $probe2 = "i90573_probe" ascii

    condition:
        uint32(0) == 0x68732123 and  /* #!/s - shebang */
        (
            (any of ($script_name*)) or
            ($backdoor_path and $staging_dir) or
            ($staging_dir and $loot_archive and 2 of ($harvest_*)) or
            ($cron_path and $task_dir) or
            (any of ($probe*))
        )
}

rule CPGuard_Backdoor_Shell
{
    meta:
        description = "Detects the setuid-root backdoor shell dropped by the cPGuard malicious update"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "critical"

    strings:
        $path = ".cpg91511_sh" ascii
        $var_tmp = "/var/tmp/" ascii

    condition:
        uint32(0) == 0x464C457F and  /* ELF magic */
        all of them
}

rule CPGuard_GSocket_Backdoor
{
    meta:
        description = "Detects gsocket backdoor installed on OPSSHIELD infrastructure during the cPGuard supply chain attack"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "critical"

    strings:
        $service_name = "defunct.service" ascii
        $binary_path = "/usr/bin/defunct" ascii
        $systemd_dat = "defunct.dat" ascii
        $fake_process = "slub_flushwq" ascii

    condition:
        2 of them
}

rule CPGuard_Go_Implant
{
    meta:
        description = "Detects Go-based implant used in the cPGuard supply chain attack on OPSSHIELD infrastructure"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "critical"

    strings:
        $typo_python = "/usr/sbin/pythno3" ascii
        $fake_netstat = "/usr/sbin/netstat.cfg" ascii
        $system_mark = "/usr/lib/system.mark" ascii
        $fake_lib = "/usr/lib/libgdi.so.0.8.2" ascii
        $boot_pub = "/boot/system.pub" ascii
        $fake_process = "rcu_gp" ascii
        $hiding = "/etc/profile.d/gateway.sh" ascii
        $bash_cfg = "/etc/profile.d/bash.cfg" ascii

    condition:
        uint32(0) == 0x464C457F and  /* ELF magic */
        3 of them
}

rule CPGuard_Webshell_Artifacts
{
    meta:
        description = "Detects web shells associated with the cPGuard supply chain attack"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "high"

    strings:
        $shell1 = "i90573_sh.php" ascii
        $shell2 = "i90573_x.php" ascii
        $probe1 = "i90248_probe.txt" ascii
        $probe2 = "i90573_probe.txt" ascii
        $rx_endpoint = "_rx.php" ascii

    condition:
        2 of them
}

rule CPGuard_Hiding_Script
{
    meta:
        description = "Detects the process-hiding mechanism used in the cPGuard supply chain attack"
        author = "Actioner CTI"
        date = "2026-11-07"
        reference = "https://opsshield.com/notice/security-incident-disclosure-servermanage.html"
        severity = "high"

    strings:
        $gateway = "/etc/profile.d/gateway.sh" ascii
        $hide_ps = "ps" ascii
        $hide_netstat = "netstat" ascii
        $hide_ls = "ls" ascii
        $hide_find = "find" ascii
        $slub = "slub_flushwq" ascii
        $rcu = "rcu_gp" ascii

    condition:
        $gateway and 2 of ($hide_*) and 1 of ($slub, $rcu)
}
