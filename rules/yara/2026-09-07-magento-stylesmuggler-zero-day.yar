rule Malware_StyleSmuggler_Rust_Backdoor
{
    meta:
        description = "Detects the StyleSmuggler Rust backdoor implant used in Magento/Adobe Commerce zero-day attacks (September 2026)"
        author = "Actioner"
        date = "2026-09-07"
        reference = "https://sansec.io/research/stylesmuggler"
        hash = "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7"
        severity = "critical"

    strings:
        $proc_name = "[kworker/u:8:0]" ascii
        $path1 = ".gvfsd/gvfsd-user" ascii
        $path2 = ".gvfsd_" ascii
        $c2_1 = "windwsecurity.run" ascii
        $c2_2 = "timesysnc.net" ascii
        $c2_3 = "microsft.run" ascii
        $c2_4 = "cdnflare.xyz" ascii
        $c2_5 = "timesync.to" ascii
        $c2_6 = "synctime.to" ascii
        $c2_7 = "microsft.studio" ascii
        $c2_8 = "syncstime.to" ascii
        $ip_check1 = "api4.ipify.org" ascii
        $ip_check2 = "icanhazip.com" ascii
        $ip_check3 = "ident.me" ascii
        $ip_check4 = "ipinfo.io" ascii

    condition:
        filesize < 5MB and
        (
            (2 of ($c2_*)) or
            ($proc_name and 1 of ($path*)) or
            (3 of ($c2_*, $ip_check*) and $proc_name)
        )
}

rule Exploit_StyleSmuggler_PHP_Dropper
{
    meta:
        description = "Detects StyleSmuggler PHP dropper code injected into Magento failure reports or log files"
        author = "Actioner"
        date = "2026-09-07"
        reference = "https://sansec.io/research/stylesmuggler"
        severity = "critical"

    strings:
        $marker = "X_TRACE_" ascii nocase
        $eval_b64 = "eval(base64_decode(" ascii nocase
        $graphql_styles = "styles[" ascii
        $proc_open = "proc_open" ascii
        $shell_exec = "shell_exec" ascii
        $passthru = "passthru" ascii
        $exec = "exec(" ascii
        $system = "system(" ascii
        $popen = "popen(" ascii
        $report_path = "var/report/" ascii

    condition:
        filesize < 1MB and
        (
            ($marker and 1 of ($eval_b64, $proc_open, $shell_exec, $passthru, $exec, $system, $popen)) or
            ($report_path and $eval_b64) or
            ($graphql_styles and $eval_b64)
        )
}
