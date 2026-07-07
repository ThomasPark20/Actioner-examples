rule PolinRider_JS_Loader_Obfuscation_Markers
{
    meta:
        description = "Detects PolinRider JavaScript loader files by distinctive obfuscation markers and decoder functions across both known variants"
        author = "Actioner"
        date = "2026-07-07"
        reference = "https://github.com/OpenSourceMalware/PolinRider"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $marker_v1 = "rmcej%otb%" ascii
        $seed1_v1 = "2857687" ascii
        $seed2_v1 = "2667686" ascii
        $decoder_v1 = "_$_1e42" ascii

        $marker_v2 = "Cot%3t=shtP" ascii
        $seed1_v2 = "1111436" ascii
        $seed2_v2 = "3896884" ascii
        $decoder_v2 = "MDy" ascii fullword

        $global_bang = "global['!']" ascii
        $global_V = "global['_V']" ascii

        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii

    condition:
        filesize < 5MB and
        (
            ($marker_v1 and 1 of ($seed1_v1, $seed2_v1, $decoder_v1)) or
            ($marker_v2 and 1 of ($seed1_v2, $seed2_v2, $decoder_v2)) or
            (1 of ($global_bang, $global_V) and 1 of ($xor_key1, $xor_key2)) or
            (1 of ($marker_v1, $marker_v2) and 1 of ($xor_key1, $xor_key2))
        )
}

rule PolinRider_Rollup_AES_Loader
{
    meta:
        description = "Detects the PolinRider Rollup polyfill AES-256-CBC loader by the distinctive scrypt passphrase and C2 endpoint pattern"
        author = "Actioner"
        date = "2026-07-07"
        reference = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $scrypt_pass = "98cb54c0b4ac259d30c9c1ca1ae87c68" ascii
        $scrypt_call = "scryptSync" ascii
        $aes_mode = "aes-256-cbc" ascii
        $c2_ip = "216.126.236.244" ascii
        $api_path = "/api/service/" ascii
        $jsonkeeper = "jsonkeeper.com" ascii

    condition:
        filesize < 1MB and
        $scrypt_pass and
        (1 of ($scrypt_call, $aes_mode)) and
        (1 of ($c2_ip, $api_path, $jsonkeeper))
}
