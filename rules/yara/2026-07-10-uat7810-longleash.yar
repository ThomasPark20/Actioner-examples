rule APT_UAT7810_LONGLEASH_Backdoor
{
    meta:
        description = "Detects LONGLEASH backdoor (internally named ff-agent v nz1.0) used by China-nexus APT UAT-7810 for ORB network operations"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f"
        severity = "high"

    strings:
        $internal_name = "ff-agent" ascii fullword
        $version = "nz1.0" ascii
        $ua = "Chrome/122.0.6261.95" ascii
        $lib_nanopb = "nanopb" ascii fullword
        $lib_mbedtls = "mbedtls" ascii nocase

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        $internal_name and
        1 of ($version, $ua, $lib_nanopb, $lib_mbedtls)
}

rule APT_UAT7810_LEASHTEST_Tool
{
    meta:
        description = "Detects LEASHTEST (iot-test) MIPS functionality testing tool used by UAT-7810 to verify compromised device capabilities"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823"
        severity = "medium"

    strings:
        $internal_name = "iot-test" ascii fullword
        $s1 = "thread" ascii
        $s2 = "async" ascii
        $s3 = "timer" ascii
        $s4 = "bind" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $internal_name and
        2 of ($s*)
}
