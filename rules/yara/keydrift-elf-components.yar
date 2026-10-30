rule APT_UAT11473_KeyDrift_ELF_Components
{
    meta:
        description = "Detects KeyDrift framework ELF components (PolyFlame/LittleFilch) by distinctive file path strings and LittleFilch control-plane field extraction marker bytes"
        author = "Actioner"
        date = "2026-10-30"
        reference = "https://blog.talosintelligence.com/uat-11473-keydrift/"
        severity = "critical"

    strings:
        // KeyDrift-specific file paths
        $path1 = "/tmp/system-vdaemon" ascii
        $path2 = "/var/tmp/vdaemon.bin" ascii
        $path3 = "/var/tmp/vdaemon.conf" ascii

        // Component shared object names
        $comp1 = "libdssl.so" ascii
        $comp2 = "libcommon.so" ascii

        // LittleFilch marker bytes for SD-WAN control-plane field extraction
        // 40 03 06: public/transport IP field marker
        // 40 0C 04: peer OMP system-IP field marker
        // 05 01 0C 06 40: key material field marker (assessed AES-256 IPsec key)
        $marker1 = { 40 03 06 }
        $marker2 = { 40 0C 04 }
        $marker3 = { 05 01 0C 06 40 }

        // SSL_read hook target (LittleFilch primary capability)
        $hook = "SSL_read" ascii fullword

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            2 of ($path*) or
            (1 of ($path*) and 1 of ($comp*)) or
            (1 of ($path*) and $hook and 2 of ($marker*))
        )
}
