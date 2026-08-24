rule SupplyChain_Rust_Arrayref_Malicious_BuildScript
{
    meta:
        description = "Detects the malicious build.rs script used in the Rust arrayref/proc-macro1 supply chain attack. Keys on the base64-encoded C2 URL fragments and the AcceptAll TLS verifier pattern."
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-poison-arrayref-rust-crate-to-push-infostealer-malware/"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"
        severity = "critical"

    strings:
        $b64_1 = "aHR0cHM6Ly8=" ascii
        $b64_2 = "MjMuMjU0Lg==" ascii
        $b64_3 = "MTY1Lg==" ascii
        $b64_4 = "MTEyOg==" ascii
        $b64_5 = "OTA4OS8=" ascii
        $accept_all = "AcceptAll" ascii
        $verify_server = "verify_server_cert" ascii
        $rust_setup = "rust-setup" ascii
        $forget = "std::mem::forget" ascii

    condition:
        filesize < 50KB and
        (3 of ($b64_*) or ($accept_all and $verify_server and $rust_setup) or ($rust_setup and $forget and 2 of ($b64_*)))
}

rule SupplyChain_Rust_Arrayref_Stage2_Payload
{
    meta:
        description = "Detects the stage-2 infostealer payload from the Rust arrayref supply chain attack via hardcoded encryption key and C2 beacon path."
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns"
        hash = "492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391"
        severity = "critical"

    strings:
        $key = "i am botking" ascii wide
        $beacon = "/49890878" ascii
        $cmd_kill = "kill" ascii fullword
        $cmd_minicfg = "minicfg" ascii fullword
        $cmd_startup = "startup" ascii fullword
        $cmd_runscript = "runscript" ascii fullword
        $login_data = "Login Data" ascii wide
        $mono_svc = "MonoService" ascii
        $mono_xpc = "MonoXpc" ascii

    condition:
        filesize < 20MB and
        ($key or ($beacon and 2 of ($cmd_*)) or (3 of ($cmd_*) and $login_data) or ($mono_svc and $mono_xpc))
}
