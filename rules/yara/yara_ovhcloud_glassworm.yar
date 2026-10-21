rule OVHcloud_CLI_Malicious_Build {
    meta:
        description = "Detects the backdoored OVHcloud CLI binary by matching the malicious build metadata embedded in the Go binary. The compromised build uses commit 5ead8ef and module version v0.15.1-0.20261013083505."
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
        reference2 = "https://thehackernews.com/2026/10/hackers-hijack-five-ovhcloud-cli.html"
        hash = "3833daffcaaaab27e4e0e0833240ffcb1df8df648f4ec0bc4a75c176e28933cb"
        severity = "critical"

    strings:
        $commit = "5ead8ef9b43d354dfb5caadff803b11afc8c5c58" ascii
        $module_version = "v0.15.1-0.20261013083505-5ead8ef9b43d" ascii
        $dirty_marker = "+dirty" ascii
        $vcs_modified = "vcs.modified=true" ascii
        $ovhcloud_module = "github.com/ovh/ovhcloud-cli" ascii

    condition:
        (uint32(0) == 0x464c457f or  // ELF
        uint16(0) == 0x5a4d or    // MZ (PE)
        uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe) and // Mach-O
        (
            ($commit and $ovhcloud_module) or
            ($module_version and $dirty_marker) or
            ($vcs_modified and $ovhcloud_module and $dirty_marker)
        )
}

rule GlassWorm_Preinstall_Loader {
    meta:
        description = "Detects the GlassWorm preinstall.js loader that uses invisible Unicode variation-selector character obfuscation and AES-256-CBC decryption. Used in the OVHcloud CLI compromise and prior npm/GitHub supply-chain attacks."
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
        reference2 = "https://checkmarx.com/zero-post/glassworm-targets-developer-ides-again-hiding-staged-malware-behind-runtime-rebuilt-loaders/"
        hash = "43df42fd79f6f81e530892b54634598770d6e496796a863c596e616bcb3fec70"
        severity = "high"

    strings:
        $aes_key = "zetqHyfDfod88zloncfnOaS9gGs90ONX" ascii
        $aes_iv = "a041fdaa0521fb5c3e26b217aaf24115" ascii
        $crypto_module = "require('crypto')" ascii
        $crypto_module2 = "require(\"crypto\")" ascii
        $aes_algo = "aes-256-cbc" ascii
        $eval_call = "eval(" ascii
        $solana_wallet = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC" ascii
        $solana_wallet2 = "6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ" ascii
        $unicode_fe00 = { FE 00 }
        $unicode_fe0f = { FE 0F }

    condition:
        filesize < 500KB and
        (
            ($aes_key and $aes_iv) or
            ($solana_wallet) or
            ($solana_wallet2) or
            ($aes_algo and ($crypto_module or $crypto_module2) and $eval_call and ($unicode_fe00 or $unicode_fe0f))
        )
}

rule GlassWorm_Stage2_Payload {
    meta:
        description = "Detects the decrypted GlassWorm stage-two payload that performs credential theft, locale checks, and Solana memo-based C2 resolution. Note: this rule detects GlassWorm broadly across campaigns, not specifically the October 2026 OVHcloud CLI variant."
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
        hash = "0f79989912572a24ba13baabb32b3fd084496271c51448d47b66fe1aedbf293c"
        severity = "high"

    strings:
        $init_json = "init.json" ascii
        $solana_rpc = "api.mainnet-beta.solana.com" ascii
        $solana_rpc2 = "solana-mainnet.gateway.tatum.io" ascii
        $ivbase64_header = "ivbase64" ascii
        $secretkey_header = "secretkey" ascii
        $wallet_addr = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC" ascii

    condition:
        filesize < 100KB and
        (
            ($wallet_addr and ($solana_rpc or $solana_rpc2)) or
            ($init_json and $ivbase64_header and $secretkey_header) or
            ($solana_rpc and $ivbase64_header and $secretkey_header)
        )
}

rule GlassWorm_Native_Addon {
    meta:
        description = "Detects GlassWorm native addon binaries (f_ex86.node, c_x64.node, w.node) used for browser credential theft, Chrome sideloading, and secret exfiltration. Note: this rule detects GlassWorm broadly across campaigns, not specifically the October 2026 OVHcloud CLI variant."
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://thehackernews.com/2026/03/glassworm-malware-uses-solana-dead.html"
        hash1 = "2ba01d4141fce7342a7f0cc330e6c08da83cfe5d4bfd1a79b69f20d2b1f4f7e5"
        hash2 = "fdba5be3da2467e642bd8710f971e6b266b30ac15f5f413892fd719d7e0bffd9"
        severity = "high"

    strings:
        $exfil_path = "/wall" ascii
        $exfil_ip = "208.85.20.124" ascii
        $exfil_ip2 = "217.69.3.152" ascii
        $c2_ip = "45.32.150.251" ascii
        $ledger_path = "led-win32" ascii
        $staging_dir = "WlpSxEJPU" ascii
        $staging_dir2 = "AGeZdIX" ascii
        $tvvdsr = "TvVdSR" ascii
        $update_ledger = "UpdateLedger" ascii
        $script_zombi = "script_zombi" ascii

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        (
            3 of ($exfil_*, $c2_*, $ledger_*) or
            2 of ($staging_dir, $staging_dir2, $tvvdsr, $update_ledger, $script_zombi) or
            ($exfil_path and ($exfil_ip or $exfil_ip2) and $c2_ip)
        )
}
