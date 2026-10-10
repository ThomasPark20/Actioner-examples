rule netscaler_deb_webshell
{
    meta:
        description = "Detects the .deb-packaged PHP web shell dropped via CVE-2026-88772 NetScaler exploitation. The web shell supports RC4-encrypted C2 communications and uses the ns_suidcmd SUID binary for privilege escalation."
        author = "Actioner"
        date = "2026-10-10"
        reference = "https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/"
        hash = "ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec"
        severity = "critical"
    strings:
        $suid = ".ns_suidcmd" ascii
        $func1 = "shell_exec" ascii nocase
        $func2 = "passthru" ascii nocase
        $func3 = "popen" ascii nocase
        $cmd1 = "wc -c <" ascii
        $info = "php=PHP_VERSION" ascii
        $ns_ver = "ns=4" ascii
    condition:
        filesize < 500KB and (($suid and any of ($func*)) or (3 of ($func*) and ($cmd1 or $info or $ns_ver)))
}
