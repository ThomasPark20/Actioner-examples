rule SupplyChain_cPGuard_Malicious_Update_Script
{
    meta:
        description = "Detects the malicious shell scripts pushed via the cPGuard update channel supply chain attack (Nov 2026). Matches on staging directory paths, loot archive name, credential harvesting targets, and persistence artifacts unique to this campaign."
        author = "Actioner"
        date = "2026-11-06"
        reference = "https://thehackernews.com/2026/11/cpguard-update-channel-hijacked-to.html"
        hash = "2c2acd988da531d133d0e17f245c49bf15781278f837543d18c95e8410eabd38"
        hash = "ffd7a47f65fa1244429baa936ae94be54676b53d2f88bc39564f24e22011de8a"
        hash = "d73919af84bf46de941db85e27fd1abc65701ef9ce6cf33bb27c5397f4a41c26"
        hash = "6add0201e9a3d02de772d561d05e0da86eb1c538686753b7adcc3aedf7366f77"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $staging_dir   = "/var/tmp/.cpg91511" ascii
        $loot_archive  = "loot.tgz" ascii
        $backdoor_path = "/var/tmp/.cpg91511_sh" ascii
        $cron_persist  = "/etc/cron.d/i93677" ascii
        $persist_dir   = "/var/tmp/.i93677" ascii

        $harvest1 = "/etc/shadow" ascii
        $harvest2 = "/root/.ssh/" ascii
        $harvest3 = "/root/.my.cnf" ascii
        $harvest4 = "/root/.s3cfg" ascii

        $script_name1 = "cpguard-v58812-i91511" ascii
        $attacker_ip  = "94.183.188.91" ascii

    condition:
        filesize < 1MB and
        (
            ($staging_dir and $loot_archive) or
            ($staging_dir and 2 of ($harvest*)) or
            ($backdoor_path and $cron_persist) or
            ($script_name1 and $attacker_ip) or
            (3 of ($staging_dir, $backdoor_path, $cron_persist, $persist_dir, $loot_archive))
        )
}
