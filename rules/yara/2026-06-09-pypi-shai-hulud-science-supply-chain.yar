rule Malware_ShaiHulud_Science_ABI3_Binary_Extension
{
    meta:
        description = "Detects malicious .abi3.so compiled extensions from the June 2026 Shai-Hulud science package wave. The extensions embed an obfuscated _index.js credential stealer and Bun runtime loader inside Rust/C++ compiled shared objects."
        author = "Actioner"
        date = "2026-06-09"
        reference = "https://www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages"
        severity = "critical"

    strings:
        $bun_loader = "oven-sh/bun/releases" ascii
        $index_js = "_index.js" ascii
        $fed1de = "fed1de59e" ascii
        $hades_desc = "Hades - The End for the Damned" ascii
        $rot_eval = "eval(function(s,n)" ascii
        $encrypt_fn = "E8()" ascii
        $github_exfil = "createCommitOnBranch" ascii
        $felix = "felixEvora" ascii

    condition:
        filesize < 100MB and
        (
            (2 of ($bun_loader, $index_js, $rot_eval, $encrypt_fn)) or
            ($fed1de and 1 of ($bun_loader, $index_js, $github_exfil)) or
            ($felix and 1 of ($hades_desc, $github_exfil, $index_js))
        )
}

rule Malware_ShaiHulud_Science_Obfuscated_JS_Stealer
{
    meta:
        description = "Detects the 5.3 MB obfuscated _index.js JavaScript credential stealer payload from the June 2026 Shai-Hulud science package wave. Features a fake LLM jailbreak prompt decoy (lines 1-99) with actual payload on line 101, wrapped in ROT-N + AES-128-GCM encryption."
        author = "Actioner"
        date = "2026-06-09"
        reference = "https://www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages"
        severity = "critical"

    strings:
        $fed1de_global = "globalThis[\"fed1de59e\"]" ascii
        $fed1de_key = "fed1de59e" ascii
        $rot_cipher = "s.replace(/[a-zA-Z]/g" ascii
        $rsa_oaep = "RSA-OAEP" ascii
        $aes_gcm = "AES-256-GCM" ascii
        $beautiful1 = "thebeautifulmarchoftime" ascii
        $beautiful2 = "thebeautifulsnadsoftime" ascii
        $hades = "Hades" ascii
        $anthropic_decoy = "api.anthropic.com/v1/api" ascii

    condition:
        filesize > 1MB and filesize < 15MB and
        (
            ($fed1de_global) or
            ($fed1de_key and 1 of ($rot_cipher, $rsa_oaep, $aes_gcm)) or
            (1 of ($beautiful*) and 1 of ($hades, $anthropic_decoy, $fed1de_key)) or
            ($rot_cipher and $rsa_oaep and 1 of ($beautiful*, $hades))
        )
}
