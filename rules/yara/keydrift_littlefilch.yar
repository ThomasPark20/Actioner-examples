rule KeyDrift_LittleFilch_SSLHook : keydrift littlefilch
{
    meta:
        description = "Detects KeyDrift LittleFilch component (libcommon.so) - SSL_read hook module that extracts SD-WAN keying material"
        author = "Actioner"
        date = "2026-10-31"
        reference = "https://blog.talosintelligence.com/uat-11473-keydrift/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // LittleFilch marker bytes used to identify key material in intercepted buffers
        $marker1 = { 40 03 06 }
        $marker2 = { 40 0C 04 }
        $marker3 = { 05 01 0C 06 40 }

        // File paths used by LittleFilch
        $path1 = "/var/tmp/vdaemon.bin" ascii
        $path2 = "/var/tmp/vdaemon.conf" ascii

        // SSL hooking indicators
        $hook1 = "SSL_read" ascii
        $hook2 = "RTLD_NEXT" ascii

        // Component identity
        $name1 = "libcommon.so" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            (2 of ($marker*) and 1 of ($path*)) or
            ($name1 and 1 of ($marker*) and 1 of ($hook*))
        )
}
