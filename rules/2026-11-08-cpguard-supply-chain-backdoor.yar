rule Supply_Chain_cPGuard_Backdoor_Script
{
    meta:
        description = "Detects malicious cPGuard update scripts from the November 2026 supply chain attack"
        author = "Actioner"
        date = "2026-11-08"
        reference = "https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html"
        hash = "2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38"
        severity = "critical"

    strings:
        $path1 = "/var/tmp/.cpg91511_sh" ascii
        $path2 = "/var/tmp/.cpg91511/" ascii
        $path3 = "/var/tmp/.i93677/" ascii
        $cron = "/etc/cron.d/i93677" ascii
        $loot = "loot.tgz" ascii
        $shadow = "/etc/shadow" ascii
        $sshkey = "/root/.ssh" ascii
        $mycnf = "/root/.my.cnf" ascii
        $script_name1 = "cpguard-v58812-i91511" ascii
        $script_name2 = "cpguard-v58812-i91511b" ascii
        $script_name3 = "cpguard-v58812-i91511c" ascii
        $script_name4 = "cpguard-v58812-i91511d" ascii

    condition:
        any of ($script_name*) or
        ($path1 and $shadow) or
        ($path2 and ($loot or $sshkey or $mycnf)) or
        ($cron and $path3) or
        (3 of ($path1, $path2, $path3, $cron, $loot))
}
