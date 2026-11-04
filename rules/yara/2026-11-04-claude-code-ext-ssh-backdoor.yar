rule Malicious_Claude_Code_Extension_SSH_Backdoor
{
    meta:
        description = "Detects the malicious Claude Code-branded Cursor extension with persistent SSH backdoor"
        author = "Actioner"
        date = "2026-11-04"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash_js_entry = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        hash_tunnel_key = "7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278"
        severity = "critical"

    strings:
        $c2_ip = "134.209.82.225" ascii wide
        $beacon_path = "/beacon" ascii
        $ssh_comment = "svc-telemetry" ascii wide
        $stk_pattern = ".stk_" ascii
        $plist_name = "com.apple.sysmond" ascii wide
        $smt_script = ".config/.smt" ascii
        $smtk_file = ".config/.smtk" ascii
        $smt_cmd = "smt.cmd" ascii
        $tunnel_flag = "-R '*:0:localhost:22'" ascii
        $key_fingerprint = "0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk" ascii

    condition:
        3 of them
}
