rule cpguard_supply_chain_attack_artifacts
{
    meta:
        description = "Detects artifacts from the cPGuard/OpsShield supply chain attack (Nov 2, 2026)"
        author = "CTI Analyst"
        date = "2026-11-04"
        reference = "https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html"
        severity = "critical"
        tlp = "white"

    strings:
        $script_name = "cpguard-v58812-i91511" ascii wide
        $staging_dir = ".cpg91511" ascii wide
        $backdoor = ".cpg91511_sh" ascii wide
        $loot_file = "loot.tgz" ascii wide
        $shadow = "/etc/shadow" ascii wide
        $passwd = "/etc/passwd" ascii wide
        $mysql_conf = "my.cnf" ascii wide
        $ssh_keys = "authorized_keys" ascii wide
        $known_hosts = "known_hosts" ascii wide
        $shell_history = ".bash_history" ascii wide
        $var_tmp_staging = "/var/tmp/.cpg91511" ascii wide

    condition:
        ($script_name or $staging_dir or $backdoor) and
        ($loot_file or $var_tmp_staging) and
        any of ($shadow, $passwd, $mysql_conf, $ssh_keys, $known_hosts, $shell_history)
}
