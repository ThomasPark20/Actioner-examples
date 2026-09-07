rule Malware_RustCrate_ProcMacro1_Payload
{
    meta:
        description = "Detects the stage-2 backdoor payloads delivered by the proc-macro1 Rust supply chain attack. Keys on the hardcoded AES key, C2 beacon path, and embedded operational strings."
        author = "Actioner"
        date = "2026-08-26"
        reference = "https://socket.dev/blog/popular-rust-crates-compromised"
        hash = "408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434"
        hash = "492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391"
        hash = "c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848"
        hash = "74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306"
        severity = "critical"

    strings:
        $aes_key = "i am botking" ascii
        $beacon_path = "/49890878" ascii
        $cmd_kill = "kill" ascii fullword
        $cmd_minicfg = "minicfg" ascii fullword
        $cmd_startup = "startup" ascii fullword
        $cmd_runscript = "runscript" ascii fullword
        $dir_azurekits = "AzureKits" ascii
        $dir_servicekit = "ServiceKit" ascii
        $bin_monoservice = "MonoService" ascii
        $bin_monoxpc = "MonoXpc" ascii
        $dropper_name = "rust-setup" ascii

    condition:
        filesize < 20MB and
        $aes_key and
        $beacon_path and
        (2 of ($cmd_*) or 2 of ($dir_*, $bin_*)) and
        $dropper_name
}

rule Malware_RustCrate_ProcMacro1_BuildScript
{
    meta:
        description = "Detects the malicious build.rs loader from the proc-macro1 typosquat crate that downloads and executes platform-specific payloads during cargo build."
        author = "Actioner"
        date = "2026-08-26"
        reference = "https://socket.dev/blog/popular-rust-crates-compromised"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"
        severity = "critical"

    strings:
        $accept_all = "AcceptAll" ascii
        $cert_verifier = "ServerCertVerifier" ascii
        $rust_crate = "rust-crate_0." ascii
        $rust_setup = "rust-setup" ascii
        $mem_forget = "mem::forget" ascii
        $payload_host = "23.254.165.112" ascii

    condition:
        filesize < 500KB and
        ($accept_all and $cert_verifier) and
        ($rust_crate or $rust_setup) and
        ($mem_forget or $payload_host)
}
