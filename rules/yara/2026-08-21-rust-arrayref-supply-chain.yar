rule rust_proc_macro1_malicious_build_script
{
    meta:
        description = "Detects the malicious build.rs from proc-macro1 typosquat crate used in the arrayref supply chain attack (August 2026). Matches base64-encoded C2 fragments and staging path."
        author = "Actioner"
        date = "2026-08-21"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"

    strings:
        $b64_1 = "aHR0cHM6Ly8=" ascii
        $b64_2 = "MjMuMjU0Lg==" ascii
        $b64_3 = "MTY1Lg==" ascii
        $b64_4 = "OTA4OS8=" ascii
        $b64_5 = "NDQz" ascii
        $staging = "/tmp/rust-setup" ascii
        $staging_win = "rust-setup.ps1" ascii
        $crate_01 = "rust-crate_0.1.0" ascii
        $crate_02 = "rust-crate_0.2.0" ascii
        $crate_04 = "rust-crate_0.4.0" ascii

    condition:
        3 of ($b64_*) or ($staging and 1 of ($crate_*)) or ($staging_win and 1 of ($crate_*))
}

rule rust_proc_macro1_stage2_implant
{
    meta:
        description = "Detects the stage-2 implant delivered by the arrayref supply chain attack. Matches the hardcoded AES passphrase, C2 path, and command strings."
        author = "Actioner"
        date = "2026-08-21"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash_linux = "408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434"
        hash_macos = "74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306"

    strings:
        $aes_key = "i am botking" ascii wide
        $c2_path = "/49890878" ascii
        $cmd_kill = "kill" ascii
        $cmd_minicfg = "minicfg" ascii
        $cmd_startup = "startup" ascii
        $cmd_runscript = "runscript" ascii
        $vbs_launcher = "rust-setup-launch.vbs" ascii

    condition:
        ($aes_key and $c2_path) or ($c2_path and 3 of ($cmd_*)) or ($vbs_launcher and $c2_path)
}

rule rust_arrayref_malicious_crate_manifest
{
    meta:
        description = "Detects Cargo.toml manifests that declare a dependency on the typosquatted proc-macro1 crate, as used in the arrayref supply chain attack."
        author = "Actioner"
        date = "2026-08-21"
        reference = "https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/"
        hash = "25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae"

    strings:
        $dep1 = "proc-macro1" ascii nocase
        $dep2 = "proc-macro-en" ascii nocase
        $cargo = "[dependencies]" ascii nocase

    condition:
        filesize < 64KB and $cargo and ($dep1 or $dep2)
}
