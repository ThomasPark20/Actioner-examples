rule SupplyChain_Rust_Arrayref_Malicious_BuildScript
{
    meta:
        description = "Detects the malicious build.rs script or payload artifacts from the compromised Rust crates (arrayref, internment, append-only-vec) supply chain attack"
        author = "Actioner"
        date = "2026-08-22"
        reference = "https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf"
        hash = "cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568"
        severity = "critical"

    strings:
        $key1 = "i am botking" ascii
        $key2 = "AcceptAll" ascii
        $payload_name1 = "rust-crate_0.1.0" ascii
        $payload_name2 = "rust-crate_0.2.0" ascii
        $payload_name3 = "rust-crate_0.3.0" ascii
        $payload_name4 = "rust-crate_0.4.0" ascii
        $path1 = "/tmp/rust-setup" ascii
        $path2 = "rust-setup.ps1" ascii
        $path3 = "rust-setup-launch.vbs" ascii
        $c2_endpoint = "/49890878" ascii
        $dep = "proc-macro1" ascii

    condition:
        3 of them
}

rule SupplyChain_Rust_Arrayref_Windows_Implant
{
    meta:
        description = "Detects the Windows PowerShell implant dropped by the compromised Rust crate supply chain attack based on known hashes and strings"
        author = "Actioner"
        date = "2026-08-22"
        reference = "https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf"
        hash = "492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391"
        severity = "critical"

    strings:
        $key = "i am botking" ascii wide
        $cmd_kill = "kill" ascii wide
        $cmd_minicfg = "minicfg" ascii wide
        $cmd_startup = "startup" ascii wide
        $cmd_runscript = "runscript" ascii wide
        $c2_path = "/49890878" ascii wide
        $browser_chrome = "Google\\Chrome\\User Data" ascii wide nocase
        $browser_brave = "BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $browser_edge = "Microsoft\\Edge\\User Data" ascii wide nocase
        $sqlite_tool = "sqlite-tools.zip" ascii wide

    condition:
        $key and $c2_path and (2 of ($cmd_*) or 2 of ($browser_*) or $sqlite_tool)
}
