rule APT_UAT7810_DOGLEASH_Backdoor
{
    meta:
        description = "Detects DOGLEASH backdoor used by UAT-7810 via command codes and shell execution pattern"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "604b53f87d6c070bf387e80c70a6df8d272fa3fc143148d41f13e59d52ab1f13"
        severity = "critical"

    strings:
        $cmd_exec = "/bin/sh -c" ascii
        $hex_cmd1 = { 22 68 }
        $hex_cmd2 = { 22 67 }
        $hex_cmd3 = { 22 66 }
        $hex_cmd4 = { 22 71 }
        $hex_cmd5 = { 22 73 }
        $hex_cmd6 = { 22 74 }
        $hex_cmd7 = { 34 50 }
        $os_info1 = "release" ascii
        $os_info2 = "version" ascii
        $os_info3 = "machine" ascii
        $os_info4 = "nodename" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $cmd_exec and
        (3 of ($hex_cmd*) and 2 of ($os_info*))
}

rule APT_UAT7810_LONGLEASH_Backdoor
{
    meta:
        description = "Detects LONGLEASH backdoor (ff-agent/nz1.0) used by UAT-7810 for ORB network operations"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f"
        severity = "critical"

    strings:
        $proj1 = "nz1.0" ascii
        $proj2 = "ff-agent" ascii
        $ua = "Chrome/122.0.6261.95" ascii
        $lib1 = "boost" ascii nocase
        $lib2 = "nanopb" ascii
        $lib3 = "mbedtls" ascii nocase
        $func1 = "Base58" ascii
        $func2 = "Base64" ascii
        $proto1 = "SOCKS" ascii
        $proto2 = "SMTP" ascii
        $proto3 = "ICMP" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (1 of ($proj*) and 2 of ($lib*)) or
            ($ua and 1 of ($lib*)) or
            (1 of ($proj*) and 1 of ($func*) and 2 of ($proto*))
        )
}

rule APT_UAT7810_JARLEASH_Backdoor
{
    meta:
        description = "Detects JARLEASH Java-based backdoor used by UAT-7810 for file management and remote access"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "324d95024fc8da5c92b5a1f4825aed5a2a91c9ca8fb6aa52abb332a4c9cf4257"
        severity = "high"

    strings:
        $pk = { 50 4B 03 04 }
        $java1 = "META-INF" ascii
        $java2 = ".class" ascii
        $ftp = "FtpServer" ascii
        $sftp = "SftpServer" ascii
        $sftp2 = "SFTP" ascii
        $netcat = "netcat" ascii nocase
        $nc = "Netcat" ascii

    condition:
        $pk at 0 and
        filesize < 50MB and
        all of ($java*) and
        (
            ($ftp and 1 of ($sftp*)) or
            ($ftp and 1 of ($nc, $netcat)) or
            (1 of ($sftp*) and 1 of ($nc, $netcat))
        )
}

rule APT_UAT7810_LEASHTEST_MIPS_Testing
{
    meta:
        description = "Detects LEASHTEST MIPS testing binary (iot-test) indicating UAT-7810 compromise"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823"
        severity = "medium"

    strings:
        $name = "iot-test" ascii
        $hw = "Hello World" ascii
        $thread = "thread" ascii
        $acceptor = "acceptor" ascii
        $timer = "async" ascii
        $child = "child" ascii
        $boost = "boost" ascii nocase

    condition:
        uint32(0) == 0x464C457F and
        filesize < 2MB and
        $name and
        $boost and
        3 of ($hw, $thread, $acceptor, $timer, $child)
}

rule APT_UAT7810_TLS_Certificate_Exploit
{
    meta:
        description = "Detects TLS certificates with all fields set to 'exploit' as used by UAT-7810 C2 infrastructure"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        severity = "high"

    strings:
        $cn = "CN=exploit" ascii
        $o = "O=exploit" ascii
        $ou = "OU=exploit" ascii
        $c = "C=exploit" ascii
        $st = "ST=exploit" ascii
        $l = "L=exploit" ascii

    condition:
        filesize < 10KB and
        4 of them
}
