rule APT_Sandworm_SopraVPN_Trojanized_WireGuard
{
    meta:
        description = "Detects trojanized WireGuard client (SopraVPN) used by UAC-0145/Sandworm with non-standard SymmetricKey config support and custom Base64 alphabet"
        author = "Actioner"
        date = "2026-08-13"
        reference = "https://cert.gov.ua/article/6318863"
        tlp = "WHITE"
        severity = "high"

    strings:
        $wg_marker1 = "WireGuard" ascii wide
        $wg_marker2 = "wireguard" ascii

        $sym_key = "SymmetricKey" ascii wide fullword
        $run_script = "runScriptCommand" ascii wide
        $post_up = "PostUp" ascii wide fullword

        $crypto1 = "AES-256-GCM" ascii wide
        $crypto2 = "AES256GCM" ascii wide

        $sopra1 = "SopraVPN" ascii wide nocase
        $sopra2 = "soprasteria" ascii wide nocase
        $sopra3 = "soprabulgaria" ascii wide nocase

        $b64_shuffle = "Fisher" ascii wide
        $crc32_seed = "CRC32" ascii wide

    condition:
        filesize < 50MB and
        1 of ($wg_marker*) and
        $sym_key and
        (
            ($run_script and 1 of ($crypto*)) or
            (2 of ($sopra*)) or
            ($run_script and ($b64_shuffle or $crc32_seed)) or
            ($post_up and $run_script and $sym_key)
        )
}
