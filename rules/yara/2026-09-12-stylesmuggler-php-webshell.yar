rule Malware_StyleSmuggler_PHP_Dropper_WebShell
{
    meta:
        description = "Detects the StyleSmuggler PHP dropper / web shell component deployed via CVE-2026-75650. The web shell requires an X-Cache-Token header and accepts PHP code via a task POST parameter."
        author = "Actioner"
        date = "2026-09-12"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        hash = "d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // Web shell authentication token header
        $auth1 = "X-Cache-Token" ascii nocase
        $auth2 = "fced27f6d57702565353ecc11722533b" ascii

        // PHP execution functions used in dropper (tries sequentially)
        $exec1 = "proc_open" ascii
        $exec2 = "shell_exec" ascii
        $exec3 = "passthru" ascii
        $exec4 = "system(" ascii
        $exec5 = "popen(" ascii
        $exec6 = "exec(" ascii

        // Dropper download behavior
        $dl1 = "247.cdnflare.xyz" ascii

        // Template injection artifacts
        $tmpl1 = "x_trace_" ascii
        $tmpl2 = "var/report/" ascii
        $tmpl3 = "setup/src/Magento/Setup/Module/Di" ascii

        // Campaign markers
        $camp1 = "ss5_457cfa2fb7" ascii
        $camp2 = "ss6_457cfa2fb7_" ascii

        // Reconnaissance callbacks
        $recon1 = "oast.site" ascii
        $recon2 = "ipify.org" ascii
        $recon3 = "icanhazip.com" ascii

    condition:
        filesize < 100KB and
        (
            ($auth1 and $auth2) or
            ($auth1 and 2 of ($exec*) and $dl1) or
            1 of ($camp*) or
            (2 of ($exec*) and $dl1 and 1 of ($tmpl*)) or
            ($auth2 and 1 of ($exec*)) or
            ($dl1 and 1 of ($recon*) and 1 of ($exec*))
        )
}
