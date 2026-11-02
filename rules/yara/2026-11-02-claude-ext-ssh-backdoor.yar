rule SupplyChain_ClaudeCode_SSH_Backdoor
{
    meta:
        description = "Detects the malicious Claude Code extension loader that plants SSH backdoor keys and reverse tunnels"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        severity = "critical"

    strings:
        $ssh_comment = "svc-telemetry" ascii wide
        $stk_pattern = ".stk_" ascii wide
        $beacon_path = "/beacon" ascii wide
        $beacon_port = "8099" ascii wide
        $smt_file = ".smt" ascii wide
        $smtk_file = ".smtk" ascii wide
        $plist_name = "com.apple.sysmond" ascii wide
        $ssh_args = "-N -R" ascii wide
        $env_key = "KEY" ascii
        $env_token = "TOKEN" ascii
        $env_secret = "SECRET" ascii
        $env_pass = "PASS" ascii

    condition:
        ($ssh_comment and $stk_pattern) or
        ($ssh_comment and $beacon_path and $beacon_port) or
        ($plist_name and ($smt_file or $smtk_file)) or
        ($stk_pattern and $ssh_args and 2 of ($env_key, $env_token, $env_secret, $env_pass))
}
