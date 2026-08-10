rule PolinRider_JavaScript_Obfuscator_MultiVariant
{
    meta:
        description = "Detects PolinRider JavaScript obfuscator payload in both original (rmcej) and rotated (Cot) variants via distinctive marker strings, shuffle seeds, and decoder functions"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://opensourcemalware.com/blog/polinrider-attack"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Original variant markers
        $marker_v1 = "rmcej%otb%" ascii
        $decoder_v1 = "_$_1e42" ascii
        $seed_v1a = "2857687" ascii
        $seed_v1b = "2667686" ascii
        $global_v1 = "global['!']" ascii

        // Rotated variant markers
        $marker_v2 = "Cot%3t=shtP" ascii
        $decoder_v2 = "function MDy(f)" ascii
        $seed_v2a = "1111436" ascii
        $seed_v2b = "3896884" ascii
        $global_v2 = "global['_V']" ascii

        // Common C2 infrastructure
        $c2_tron = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" ascii
        $c2_tron2 = "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" ascii
        $c2_vercel1 = "default-configuration.vercel.app" ascii
        $c2_vercel2 = "vscode-settings-bootstrap.vercel.app" ascii

        // XOR decryption keys
        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii

        // Propagation artifact
        $prop = "temp_auto_push.bat" ascii

        // StakingGame UUID
        $uuid = "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9" ascii

    condition:
        filesize < 5MB and
        (
            // Original variant: marker + any supporting indicator
            ($marker_v1 and (1 of ($decoder_v1, $seed_v1a, $seed_v1b, $global_v1))) or
            // Rotated variant: marker + any supporting indicator
            ($marker_v2 and (1 of ($decoder_v2, $seed_v2a, $seed_v2b, $global_v2))) or
            // C2 infrastructure indicators (2+ for confidence)
            (2 of ($c2_*)) or
            // XOR keys with any C2 or marker
            (1 of ($xor_key*) and 1 of ($c2_*, $marker_*)) or
            // StakingGame UUID
            ($uuid and 1 of ($c2_*)) or
            // Propagation artifact with markers
            ($prop and 1 of ($marker_*, $c2_*))
        )
}

rule PolinRider_TempAutoPush_Propagation
{
    meta:
        description = "Detects the PolinRider temp_auto_push.bat propagation script that rewrites git history with spoofed timestamps"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://github.com/OpenSourceMalware/PolinRider"
        severity = "high"
        tlp = "WHITE"

    strings:
        $s1 = "LAST_COMMIT_DATE" ascii
        $s2 = "LAST_COMMIT_TIME" ascii
        $s3 = "git commit" ascii nocase
        $s4 = "--amend" ascii
        $s5 = "--no-verify" ascii
        $s6 = "git log -1" ascii
        $s7 = "git push" ascii nocase
        $s8 = "-uf" ascii

    condition:
        filesize < 50KB and
        (1 of ($s1, $s2)) and 3 of ($s3, $s4, $s5, $s6, $s7, $s8)
}
