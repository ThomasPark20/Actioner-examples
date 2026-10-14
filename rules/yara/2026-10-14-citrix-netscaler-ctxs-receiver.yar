rule Exploit_CVE_2026_88771_NetScaler_WebShell_CTXReceiver
{
    meta:
        description = "Detects the .ctxs.receiver PHP web shell dropped by CVE-2026-88771 exploitation, keying on the hardcoded CsrfToken, cookie name, and passthru call"
        author = "Actioner"
        date = "2026-10-14"
        reference = "https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/"
        hash = "6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7"
        severity = "critical"

    strings:
        $csrf = "e826d7ddf3c85920" ascii
        $cookie = "NSC_TASS" ascii
        $passthru = "passthru(" ascii
        $php_open = "<?php" ascii nocase

    condition:
        filesize < 50KB and
        $php_open and
        $csrf and
        ($cookie or $passthru)
}
