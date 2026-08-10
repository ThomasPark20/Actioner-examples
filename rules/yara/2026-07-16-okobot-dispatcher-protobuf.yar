rule Malware_OkoBot_Dispatcher_Protobuf
{
    meta:
        description = "Detects OkoBot dispatcher component (protobuf.dll) via characteristic plugin dispatch and HWID validation patterns"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://securelist.com/okobot-framework-targets-cryptocurrency-wallets/120660/"
        severity = "high"

    strings:
        $s1 = "hwid.dat" ascii wide
        $s2 = "oko_ver" ascii wide
        $s3 = "protobuf.dll" ascii wide
        $path1 = "HDVideo" ascii wide
        $path2 = "HDUtil" ascii wide
        $cmd1 = "target" ascii
        $cmd2 = "nouac" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($s1 and $s2) or
            ($s3 and 2 of ($path*, $cmd*)) or
            (3 of them)
        )
}
