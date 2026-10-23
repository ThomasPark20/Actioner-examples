rule Malware_Mirai_Potassium_PHP2Shell
{
    meta:
        description = "Mirai Potassium variant (nfs dropper) deployed via PHP2Shell exploitation; keyed on process-masquerade name set plus /dev/shm probe path, or plaintext C2 domains"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://ellio.tech/en/blog/php2shell-what-we-observed-and-what-to-do/"
        hash = "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486"
        confidence = "medium"
        note = "Not tested against a positive sample. C2 config is ChaCha20-encrypted per ELLIO, so domain strings may not appear in cleartext; the masquerade+shm clause is the primary logic."

    strings:
        $c2_domain = "godofthunder.st" ascii
        $update_domain = "botlesscucks.st" ascii
        $dead_domain = "gettingheadfromduckysmom.st" ascii
        $proc1 = "telnetd" ascii fullword
        $proc2 = "udhcpc" ascii fullword
        $proc3 = "upnpd" ascii fullword
        $proc4 = "watchdog" ascii fullword
        $proc5 = "syslogd" ascii fullword
        $proc6 = "uhttpd" ascii fullword
        $proc7 = "klogd" ascii fullword
        $shm_path = "/dev/shm/.cache.so" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 500KB and
        (
            (3 of ($proc*) and $shm_path) or
            (2 of ($c2_domain, $update_domain, $dead_domain))
        )
}
