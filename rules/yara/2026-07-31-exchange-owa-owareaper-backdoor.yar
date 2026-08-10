rule APT_TA458_OWAReaper_Payload
{
    meta:
        description = "TTP-derived heuristic: detects OWAReaper JavaScript backdoor payload targeting Exchange OWA via CVE-2026-42897, based on distinctive Outlook API abuse strings and C2 command structure"
        author = "Actioner"
        date = "2026-07-31"
        reference = "https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/"
        severity = "low"

    strings:
        $api1 = "GetClientAccessToken" ascii wide
        $api2 = "ReadWriteMailbox" ascii wide
        $api3 = "UpdateFolder" ascii wide

        $cmd1 = "domn" ascii
        $cmd2 = "cmnd" ascii

        $persist1 = "IndexedDB" ascii wide
        $persist2 = "localStorage" ascii wide

        $c2_1 = "search/commits" ascii wide
        $c2_2 = "AES-CTR" ascii wide

    condition:
        filesize < 5MB and
        (all of ($api*)) and
        (all of ($cmd*)) and
        (1 of ($persist*) or 1 of ($c2_*))
}
