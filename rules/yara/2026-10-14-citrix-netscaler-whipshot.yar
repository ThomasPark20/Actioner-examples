rule Exploit_CVE_2026_88772_NetScaler_WebShell_WHIPSHOT
{
    meta:
        description = "Detects the WHIPSHOT PHP web shell (nsg64.deb) used in CVE-2026-88772 exploitation, keying on the RC4 key and hardcoded passphrase"
        author = "Actioner"
        date = "2026-10-14"
        reference = "https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/"
        hash = "ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec"
        severity = "critical"

    strings:
        $rc4_key = "7489a0f93c67fa5cdaeb4b921d90594d" ascii
        $passphrase = "Rhfajaf1H992" ascii
        $ns_suid = ".ns_suidcmd" ascii
        $cmd_dl = "\"dl\"" ascii
        $cmd_up = "\"up\"" ascii
        $cmd_info = "\"info\"" ascii
        $ns_marker = "ns=4" ascii

    condition:
        filesize < 200KB and
        ($rc4_key or $passphrase) and
        (2 of ($cmd_dl, $cmd_up, $cmd_info, $ns_marker, $ns_suid))
}
