rule SupplyChain_ClaudeCode_Backdoor_Loader
{
    meta:
        description = "Detects the malicious JavaScript loader injected into the trojanized Claude Code VS Code extension (v2.1.313) distributed via the Cursor marketplace"
        author = "Actioner"
        date = "2026-10-31"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $beacon = "134.209.82.225" ascii
        $beacon_port = "8099" ascii
        $beacon_path = "/beacon" ascii
        $ssh_key_comment = "svc-telemetry" ascii
        $tunnel_flag1 = "-N" ascii
        $tunnel_flag2 = "-R" ascii
        $tunnel_target = "localhost:22" ascii
        $persist_mac = "com.apple.sysmond" ascii
        $persist_file1 = ".smt" ascii
        $persist_file2 = ".smtk" ascii
        $stk_pattern = ".stk_" ascii
        $env_pattern1 = "TOKEN" ascii
        $env_pattern2 = "SECRET" ascii
        $env_pattern3 = "PASS" ascii
        $ipify = "api.ipify.org" ascii
        $git_email = "git config --global user.email" ascii

    condition:
        filesize < 10MB and
        $beacon and
        $beacon_port and
        $beacon_path and
        $ssh_key_comment and
        $stk_pattern and
        3 of ($tunnel_flag1, $tunnel_flag2, $tunnel_target, $persist_mac, $persist_file1, $persist_file2) and
        1 of ($env_pattern*, $ipify, $git_email)
}
