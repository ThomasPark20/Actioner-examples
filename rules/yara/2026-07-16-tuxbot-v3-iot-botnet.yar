rule Botnet_TuxBot_v3_ELF_Binary
{
    meta:
        description = "Detects TuxBot v3 IoT botnet binaries via distinctive embedded strings including LLM-generated safety disclaimer, bot identifier, and C2 configuration artifacts"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/"
        hash = "15c17dce89deccd5172285b2650de957918aa1157cde8e4633ae15dfe31f2711"
        severity = "critical"

    strings:
        $disclaimer = "WARNING: This code is for educational and authorized security research only" ascii
        $banner = "Infected By Akiru" ascii
        $busybox = "/bin/busybox Akiru" ascii
        $applet = "Akiru: applet not found" ascii
        $service = "sd-pam.service" ascii
        $lock = "/tmp/.%08x.lock" ascii
        $dga_seed = "TuxBotv3-Evolution-Seed-2025" ascii
        $cred_comment = "// START IMPORTED FROM DDOS-ROOTSEC pass_file" ascii
        $handshake_magic = { DE AD BE 01 }
        $packet_magic = { DE AD BE EF }

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            3 of ($disclaimer, $banner, $busybox, $applet, $dga_seed, $cred_comment) or
            ($banner and $lock and $service) or
            ($handshake_magic and $packet_magic and 1 of ($banner, $busybox, $dga_seed))
        )
}
