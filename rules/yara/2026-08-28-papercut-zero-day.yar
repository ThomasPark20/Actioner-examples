rule Exploit_PaperCut_2026_Malicious_Class
{
    meta:
        description = "Detects malicious Java .class files used in the August 2026 PaperCut NG/MF pre-auth RCE exploitation, based on strings from Udydn.class and Moo97.class payloads"
        author = "Actioner"
        date = "2026-08-28"
        reference = "https://www.huntress.com/blog/papercut-actively-exploited"
        severity = "critical"

    strings:
        $class_magic = { CA FE BA BE }

        $s1 = "Udydn" ascii
        $s2 = "Moo97" ascii
        $s3 = "data/content/" ascii
        $s4 = ".out" ascii
        $s5 = ".cmd" ascii
        $s6 = "derby.log" ascii
        $s7 = "server.log" ascii

        $cmd_win = "cmd.exe" ascii
        $cmd_nix = "/bin/sh" ascii

    condition:
        $class_magic at 0 and
        filesize < 50KB and
        (
            ($s1 and 2 of ($s3, $s4, $s5, $s6, $s7)) or
            ($s2 and 2 of ($s3, $s4, $s5, $s6, $s7)) or
            (3 of ($s3, $s4, $s5, $s6, $s7) and ($cmd_win or $cmd_nix))
        )
}
