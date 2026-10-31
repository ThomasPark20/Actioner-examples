rule KeyDrift_aaamgrd_Loader : keydrift loader
{
    meta:
        description = "Detects KeyDrift aaamgrd packed ELF loader with anti-debug capabilities deployed on SD-WAN Validators"
        author = "Actioner"
        date = "2026-10-31"
        reference = "https://blog.talosintelligence.com/uat-11473-keydrift/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Anti-debug: TracerPid check pattern
        $antidebug1 = "TracerPid:" ascii
        $antidebug2 = "/proc/%d/status" ascii

        // Process names being masqueraded
        $masq1 = "aaamgrd" ascii fullword
        $masq2 = "aaamgr" ascii fullword

        // Ptrace-based injection
        $syscall1 = "ptrace" ascii fullword

        // Staging paths
        $path1 = "/etc/sv/aaamgr/" ascii
        $path2 = "/var/tmp/vdaemon.bin" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            ($antidebug1 and $syscall1 and 1 of ($masq*)) or
            (1 of ($antidebug*) and $syscall1 and 1 of ($path*))
        )
}
