// YARA rules for Rust Crate Supply Chain Attack via proc-macro1 (2026-08-25)
// Report: summaries/2026-08-25-rust-supply-chain-attack.md

import "hash"

rule SupplyChain_RustCrate_ProcMacro1_BuildScript
{
    meta:
        description = "Detects the malicious build.rs dropper from the proc-macro1 Rust supply chain attack that downloads and executes platform-specific backdoors during cargo build"
        author = "Actioner"
        date = "2026-08-25"
        reference = "https://socket.dev/blog/popular-rust-crates-compromised"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"
        severity = "critical"

    strings:
        $src_url = "SRC_URL_PARTS" ascii
        $end_url = "END_URL_PARTS" ascii
        $payload1 = "rust-crate_0.1.0" ascii
        $payload2 = "rust-crate_0.2.0" ascii
        $payload3 = "rust-crate_0.3.0" ascii
        $payload4 = "rust-crate_0.4.0" ascii
        $drop_unix = "/tmp/rust-setup" ascii
        $drop_win = "rust-setup.ps1" ascii
        $drop_vbs = "rust-setup-launch.vbs" ascii
        $tls_bypass = "AcceptAll" ascii
        $forget = "std::mem::forget" ascii
        $dep_ureq = "ureq" ascii

    condition:
        filesize < 100KB and
        (
            (3 of ($src_url, $end_url, $tls_bypass, $forget, $dep_ureq)) or
            (2 of ($payload*)) or
            (1 of ($drop_unix, $drop_win, $drop_vbs) and 1 of ($payload*))
        )
}

rule SupplyChain_RustCrate_Stage2_Backdoor
{
    meta:
        description = "Detects the stage-2 cross-platform backdoor dropped by the proc-macro1 Rust supply chain attack, targeting browser credentials and establishing persistent C2"
        author = "Actioner"
        date = "2026-08-25"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash = "408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434"
        severity = "critical"

    strings:
        $c2_path = "/49890878" ascii
        $enc_key = "i am botking" ascii wide
        $cmd1 = "minicfg" ascii
        $cmd2 = "runscript" ascii
        $cmd3 = "startup" ascii
        $persist_dir1 = "AzureKits" ascii
        $persist_dir2 = "ServiceKit" ascii
        $persist_bin1 = "MonoService" ascii
        $persist_bin2 = "MonoXpc" ascii
        $browser1 = "Login Data" ascii wide
        $browser2 = "Web Data" ascii wide

    condition:
        filesize < 20MB and
        (
            ($c2_path and $enc_key) or
            ($enc_key and 2 of ($cmd*)) or
            (2 of ($persist_dir*, $persist_bin*) and $c2_path) or
            ($c2_path and 1 of ($cmd*) and 1 of ($browser*))
        )
}

rule SupplyChain_RustCrate_Malicious_Crate_Archive
{
    meta:
        description = "Detects known malicious .crate archives and stage-2 binaries from the proc-macro1 supply chain attack by SHA-256 hash, with a secondary content-based branch for archive scanning"
        author = "Actioner"
        date = "2026-08-25"
        reference = "https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack"
        hash1 = "61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4"
        hash2 = "25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae"
        hash3 = "b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436"
        severity = "critical"

    strings:
        // Gzip magic bytes (crate archives are .tar.gz)
        $gzip_magic = { 1f 8b }
        // Tar archive signature at offset 257
        $tar_magic = { 75 73 74 61 72 }
        // Content strings for secondary detection
        $crate_name = "proc-macro1" ascii
        $version107 = "1.0.107" ascii
        $build_rs = "build.rs" ascii
        $arrayref_mal = "arrayref" ascii
        $version310 = "0.3.10" ascii

    condition:
        filesize < 20MB and
        (
            // Primary: exact hash match against known malicious files
            hash.sha256(0, filesize) == "61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4" or
            hash.sha256(0, filesize) == "25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae" or
            hash.sha256(0, filesize) == "b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436" or
            hash.sha256(0, filesize) == "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568" or
            hash.sha256(0, filesize) == "408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434" or
            hash.sha256(0, filesize) == "492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391" or
            hash.sha256(0, filesize) == "c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848" or
            hash.sha256(0, filesize) == "74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306" or
            // Secondary: archive with malicious content patterns (requires archive magic bytes)
            (
                ($gzip_magic at 0 or $tar_magic at 257) and
                $build_rs and
                (
                    ($crate_name and $version107) or
                    ($arrayref_mal and $version310 and $crate_name)
                )
            )
        )
}
