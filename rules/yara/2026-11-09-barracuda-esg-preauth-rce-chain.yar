rule Exploit_Barracuda_ESG_Crafted_Backup_CVE_2026_116606
{
    meta:
        description = "Detects crafted Barracuda ESG backup archives used in the CVE-2026-116606 / CVE-2026-111560 exploit chain. Matches tar archives containing MySQL dump-like content with timezone field injection patterns."
        author = "Actioner"
        date = "2026-11-09"
        reference = "https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection"
        severity = "high"
        tlp = "WHITE"

    strings:
        $tar_magic = { 75 73 74 61 72 }
        $sql_insert = "INSERT INTO" ascii nocase
        $timezone_field = "system_timezone" ascii nocase
        $inject1 = "$()" ascii
        $inject2 = "`" ascii
        $inject3 = "&&" ascii
        $inject4 = "||" ascii
        $bayesian = "bayesian" ascii nocase
        $spam_config = "Spam_Config" ascii nocase

    condition:
        $tar_magic at 257 and
        filesize < 5MB and
        $sql_insert and $timezone_field and
        1 of ($inject*) and
        ($bayesian or $spam_config)
}

rule Tool_WatchTowr_Barracuda_ESG_PoC_CVE_2026_116606
{
    meta:
        description = "Detects the watchTowr Detection Artifact Generator / PoC tool for CVE-2026-116606 and CVE-2026-111560 Barracuda ESG exploit chain"
        author = "Actioner"
        date = "2026-11-09"
        reference = "https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560"
        severity = "medium"
        tlp = "WHITE"

    strings:
        $s1 = "watchTowr-vs-Barracuda" ascii
        $s2 = "CVE-2026-116606" ascii
        $s3 = "CVE-2026-111560" ascii
        $s4 = "pu_bayesian_upload" ascii
        $s5 = "UPDATE_activation_code" ascii
        $s6 = "/cgi-mod/index.cgi" ascii
        $s7 = "Built backup" ascii
        $s8 = "Uploading Backup" ascii
        $s9 = "SinSinology" ascii

    condition:
        filesize < 500KB and
        3 of them
}
