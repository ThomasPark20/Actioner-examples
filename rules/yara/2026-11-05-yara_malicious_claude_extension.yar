rule Malicious_Claude_Code_Extension_JS_Payload {
    meta:
        description = "Detects the backdoored extension.js payload from the malicious Claude Code Cursor extension that installs an SSH backdoor."
        author = "Actioner"
        date = "2026-11-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        hash = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        severity = "critical"

    strings:
        $ssh_key_comment = "svc-telemetry" ascii wide
        $beacon_path = "/beacon" ascii wide
        $attacker_ip = "134.209.82.225" ascii wide
        $tunnel_user = "tunnel@" ascii wide
        $ssh_reverse = "-R '*:0:localhost:22'" ascii wide
        $env_regex = /KEY|TOKEN|SECRET|PASS|AWS|GCP/ ascii wide
        $config_smt = ".config/.smt" ascii wide
        $config_smtk = ".config/.smtk" ascii wide
        $sysmond_plist = "com.apple.sysmond" ascii wide
        $stk_prefix = ".stk_" ascii wide
        $ssh_opts = "StrictHostKeyChecking=no" ascii wide

    condition:
        filesize < 20MB and
        (
            ($ssh_key_comment and $attacker_ip) or
            ($beacon_path and $attacker_ip) or
            ($tunnel_user and $attacker_ip) or
            (4 of ($ssh_key_comment, $config_smt, $config_smtk, $sysmond_plist, $stk_prefix, $ssh_reverse, $ssh_opts, $env_regex))
        )
}

rule Malicious_Claude_Code_Extension_VSIX {
    meta:
        description = "Detects known malicious Claude Code extension VSIX packages by embedded artifact patterns."
        author = "Actioner"
        date = "2026-11-05"
        reference = "https://cursor.com/blog/claude-code-extension-security-notice"
        severity = "critical"

    strings:
        $vsix_marker = "[Content_Types].xml" ascii
        $ext_id = "anthropic.claude-code" ascii wide
        $ssh_key_comment = "svc-telemetry" ascii wide
        $attacker_ip = "134.209.82.225" ascii wide
        $beacon = ":8099/beacon" ascii wide

    condition:
        filesize < 100MB and
        $vsix_marker and
        $ext_id and
        ($ssh_key_comment or $attacker_ip or $beacon)
}

rule Malicious_Claude_Code_Persistence_Script {
    meta:
        description = "Detects the SSH tunnel persistence shell script or batch file dropped by the malicious Claude Code extension."
        author = "Actioner"
        date = "2026-11-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"
        severity = "high"

    strings:
        $ssh_reverse_fwd = "-R '*:0:localhost:22'" ascii wide
        $tunnel_user = "tunnel@134.209.82.225" ascii wide
        $strict_host = "StrictHostKeyChecking=no" ascii wide
        $identity_file_smt = ".config/.smtk" ascii wide
        $identity_file_stk = ".stk_" ascii wide
        $sleep_retry = "sleep 60" ascii wide
        $autossh = "autossh -M 0" ascii wide

    condition:
        filesize < 10KB and
        (
            $tunnel_user or
            ($ssh_reverse_fwd and $strict_host) or
            ($identity_file_smt and ($sleep_retry or $autossh)) or
            ($identity_file_stk and ($sleep_retry or $autossh))
        )
}

rule Malicious_Claude_Code_SSH_Private_Key {
    meta:
        description = "Detects the tunnel private key file dropped by the malicious Claude Code extension, identified by known fingerprint context."
        author = "Actioner"
        date = "2026-11-05"
        reference = "https://cursor.com/blog/claude-code-extension-security-notice"
        hash = "7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278"
        severity = "critical"

    strings:
        $key_header = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $key_comment_tun = "svc-telemetry-tun" ascii

    condition:
        filesize < 1KB and
        $key_header and $key_comment_tun
}
