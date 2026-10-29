rule Malware_NIK_C2_Agent : trojan rat
{
    meta:
        description = "Detects NIK C2 agent binary via distinctive strings including build path, log marker, AES key, and C2 endpoint patterns"
        author = "Actioner"
        date = "2026-10-29"
        reference = "https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/"
        severity = "critical"

    strings:
        $build_path = "/opt/nik_panel/data/build_" ascii
        $log_marker = "[NIK] Starting" ascii wide
        $aes_seed = "d791dd0ff3228ed29a8d7333d4567be829159c5632ea347780992006f91c5295" ascii nocase
        $aes_key = "4887AFC0A574E9419A9695EF083460F58E4EF9A1C40793523CE112251273BDF9" ascii nocase
        $endpoint1 = "/api/c2/update" ascii
        $endpoint2 = "/api/c2/result" ascii
        $endpoint3 = "/api/c2/screen" ascii
        $endpoint4 = "/api/c2/ws" ascii
        $endpoint5 = "/api/c2/file_chunk" ascii
        $endpoint6 = "/api/c2/rproxy_up" ascii
        $c2_domain = "total-sitevv.lol" ascii wide
        $panel_str = "nik-panel" ascii wide
        $mbr_file = "mbr_backup.bin" ascii wide
        $lock_file = "lock_screen.html" ascii wide
        $seed_regex = "seed|phrase|mnemonic|recovery" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 30MB and
        (
            $build_path or
            $log_marker or
            ($aes_seed and 1 of ($endpoint*)) or
            ($aes_key and 1 of ($endpoint*)) or
            (3 of ($endpoint*) and ($c2_domain or $panel_str)) or
            ($mbr_file and $lock_file and 1 of ($endpoint*)) or
            ($seed_regex and $c2_domain)
        )
}
