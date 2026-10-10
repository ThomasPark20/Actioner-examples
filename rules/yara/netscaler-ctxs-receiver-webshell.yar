rule netscaler_ctxs_receiver_webshell
{
    meta:
        description = "Detects the .ctxs.receiver PHP web shell deployed via CVE-2026-88771 NetScaler exploitation. The shell checks a CsrfToken cookie and passes the NSC_TASS cookie contents to passthru() for command execution."
        author = "Actioner"
        date = "2026-10-10"
        reference = "https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/"
        hash = "79c65fa04541032e251fa4796b97800374b63c7982593dd1a2e0db605d429186"
        severity = "critical"
    strings:
        $cookie1 = "CsrfToken" ascii nocase
        $cookie2 = "NSC_TASS" ascii nocase
        $func1 = "passthru" ascii nocase
        $func2 = "urldecode" ascii nocase
        $path1 = ".ctxs.receiver" ascii
        $path2 = "LogonPoint" ascii
    condition:
        filesize < 100KB and (($cookie1 and $cookie2 and $func1) or ($path1 and $func1 and $cookie2) or ($func1 and $func2 and $cookie2) or ($path2 and $path1))
}
