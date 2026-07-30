rule APT_TA488_OWAReaper_JavaScript_Implant
{
    meta:
        description = "Detects OWAReaper JavaScript implant via distinctive string combinations: OAuth token theft API, EWS folder permission modification, GitHub C2 endpoint, and custom command type identifiers"
        author = "Actioner"
        date = "2026-07-30"
        reference = "https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/"
        severity = "critical"

    strings:
        $api1 = "GetClientAccessToken" ascii wide
        $api2 = "UpdateFolder" ascii wide
        $c2_github = "search/commits" ascii wide
        $cmd_exec = "cmnd" ascii fullword
        $cmd_rotate = "domn" ascii fullword
        $cmd_replace = "code" ascii fullword
        $persist_ls = "localStorage" ascii wide
        $persist_idb = "indexedDB" ascii wide nocase
        $crypto = "AES-CTR" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            ($api1 and $api2 and 1 of ($cmd*)) or
            ($c2_github and $cmd_exec and $cmd_rotate and $cmd_replace) or
            ($api1 and $c2_github and $crypto) or
            (1 of ($api*) and $c2_github and 1 of ($persist*) and 1 of ($cmd*))
        )
}
