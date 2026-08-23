rule Malware_RedC2_RedShell_ELF_Implant
{
    meta:
        description = "Detects RedC2 4.0 RedShell Linux ELF implant based on characteristic capability strings for interactive shell, credential theft, and C2 communication. Requires distinctive RedC2/RedShell identifier."
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html"
        severity = "high"

    strings:
        $elf = { 7F 45 4C 46 }

        $s1 = "/bin/sh" ascii
        $s2 = ".ssh/authorized_keys" ascii
        $s3 = ".ssh/id_rsa" ascii
        $s4 = "SOCKS5" ascii nocase
        $s5 = "RedShell" ascii nocase
        $s6 = "RedC2" ascii nocase
        $s7 = "red_agent" ascii nocase
        $s8 = "beacon" ascii nocase

        $cred1 = "Login Data" ascii
        $cred2 = "chrome" ascii nocase
        $cred3 = "firefox" ascii nocase
        $cred4 = "chromium" ascii nocase

    condition:
        $elf at 0 and
        filesize < 50MB and
        (
            (($s5 or $s6) and 4 of ($s*) and 2 of ($cred*)) or
            ($s5 and $s6 and 3 of ($s*))
        )
}
