rule KeyDrift_PolyFlame_Backdoor : keydrift polyflame
{
    meta:
        description = "Detects KeyDrift PolyFlame component (libdssl.so) - memory-resident backdoor injected into vdaemon processes"
        author = "Actioner"
        date = "2026-10-31"
        reference = "https://blog.talosintelligence.com/uat-11473-keydrift/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Hooked function names used by PolyFlame for runtime interposition
        $hook1 = "recvfrom" ascii fullword
        $hook2 = "sendto" ascii fullword
        $hook3 = "getpeername" ascii fullword
        $hook4 = "dlopen" ascii fullword
        $hook5 = "dlsym" ascii fullword
        $hook6 = "mprotect" ascii fullword

        // RTLD_NEXT hooking pattern
        $rtld = "RTLD_NEXT" ascii

        // Component name
        $name1 = "libdssl.so" ascii

        // Staging file paths
        $path1 = "/var/tmp/vdaemon.bin" ascii
        $path2 = "/tmp/system-vdaemon" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            ($name1 and 3 of ($hook*) and $rtld) or
            (1 of ($path*) and 3 of ($hook*) and $rtld)
        )
}
