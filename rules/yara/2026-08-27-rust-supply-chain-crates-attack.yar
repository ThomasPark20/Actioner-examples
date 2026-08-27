rule Malware_Rust_Supply_Chain_Proc_Macro1_BuildScript
{
    meta:
        description = "Detects the malicious proc-macro1 build script used in the Rust crates supply chain attack (arrayref, internment, append-only-vec). Keys on distinctive strings: AES-128-GCM config key, C2 beacon path, and payload file names."
        author = "Actioner"
        date = "2026-08-27"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash = "61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4"
        severity = "critical"

    strings:
        $key = "i am botking" ascii wide
        $beacon = "/49890878" ascii wide
        $drop_unix = "/tmp/rust-setup" ascii
        $drop_win1 = "rust-setup.ps1" ascii wide
        $drop_win2 = "rust-setup-launch.vbs" ascii wide
        $cmd1 = "minicfg" ascii
        $cmd2 = "runscript" ascii
        $cmd3 = "startup" ascii

    condition:
        filesize < 10MB and
        (
            $key or
            ($beacon and 1 of ($drop*)) or
            (2 of ($drop*) and 1 of ($cmd*)) or
            (3 of ($cmd*) and 1 of ($drop*))
        )
}

rule Malware_Rust_Supply_Chain_Stage2_Payload
{
    meta:
        description = "Detects the stage-2 implant payload from the Rust crates supply chain attack via distinctive command strings and configuration key."
        author = "Actioner"
        date = "2026-08-27"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        severity = "critical"

    strings:
        $key = "i am botking" ascii
        $cmd_kill = "kill" ascii fullword
        $cmd_minicfg = "minicfg" ascii fullword
        $cmd_startup = "startup" ascii fullword
        $cmd_runscript = "runscript" ascii fullword
        $c2_path = "/49890878" ascii
        $host = "hostwindsdns.com" ascii

    condition:
        filesize < 10MB and
        $key and
        (2 of ($cmd*) or $c2_path or $host)
}
