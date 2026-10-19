rule Malware_MALFEX_Go_Downloader
{
    meta:
        description = "Detects the MALFEX Go-based stage-2 downloader that fetches setup.exe from the C2 server"
        author = "Actioner"
        date = "2026-10-19"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash = "2f268ca76ab27971d8b16bd4ded26e1f9cd3d4460b894af2d4bdf89f0ab7ec4b"
        severity = "high"

    strings:
        $mod = "downloader" ascii fullword
        $c2_1 = "104.234.65.75" ascii
        $c2_2 = "setup.exe" ascii
        $path1 = "svc_update.exe" ascii
        $go = "Go build" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $c2_1 and
        ($go or 1 of ($mod, $path1, $c2_2))
}
