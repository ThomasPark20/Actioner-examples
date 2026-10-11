rule GhostAction_Malicious_Workflow_Oct2026 : supply_chain
{
    meta:
        description = "Detects GhostAction malicious GitHub Actions workflow files used to steal CI/CD secrets and cloud credentials via exfiltration to 193.32.204.199"
        author = "Actioner"
        date = "2026-10-11"
        reference = "https://www.stepsecurity.io/blog/ghostaction-returns"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // C2 IP addresses - current and legacy
        $c2_current = "193.32.204.199" ascii
        $c2_legacy1 = "170.39.218.2" ascii
        $c2_legacy2 = "45.139.104.115" ascii

        // Exfiltration body markers unique to GhostAction
        $marker1 = "AKIA_CTX_START" ascii
        $marker2 = "AKIA_CTX_END" ascii
        $marker3 = "REPO=" ascii

        // URL query parameters used in exfiltration
        $param1 = "?c=monami" ascii
        $param2 = "?c=new" ascii
        $param3 = "?inj=" ascii

        // Workflow structure indicators
        $wf_name1 = "Security Audit" ascii
        $wf_name2 = "Github Actions Security" ascii
        $wf_name3 = "Security Check" ascii

        // Git history mining pattern
        $gitlog = "git log -p --all" ascii

        // Secret scanning patterns used by the payload
        $secret1 = "AKIA" ascii
        $secret2 = "ASIA" ascii
        $fetch_depth = "fetch-depth: 0" ascii

    condition:
        filesize < 50KB and
        (
            (any of ($c2_*) and any of ($marker*)) or
            (any of ($c2_*) and any of ($param*)) or
            (any of ($c2_*) and $gitlog and $fetch_depth) or
            (2 of ($marker*) and any of ($wf_name*)) or
            (any of ($c2_*) and any of ($wf_name*) and ($secret1 or $secret2) and $fetch_depth)
        )
}

rule GhostAction_Workflow_HistoryMining : supply_chain
{
    meta:
        description = "Detects GhostAction October 2026 variant workflow that mines full git history for cloud and AI credentials"
        author = "Actioner"
        date = "2026-10-11"
        reference = "https://socket.dev/blog/ghostaction-cloud-credentials"
        severity = "high"
        tlp = "WHITE"

    strings:
        // Workflow triggers for the malicious pattern
        $trigger1 = "workflow_dispatch" ascii
        // Full history checkout
        $checkout = "fetch-depth: 0" ascii

        // Git history search
        $gitlog = "git log -p --all" ascii

        // Credential patterns scanned by the payload
        $cred_aws = "AKIA" ascii
        $cred_anthropic = "sk-ant-" ascii
        $cred_openai = "sk-proj-" ascii
        $cred_openrouter = "sk-or-" ascii
        $cred_github_pat = "ghp_" ascii
        $cred_gitlab = "glpat-" ascii

        // Exfiltration markers
        $exfil1 = "AKIA_CTX_START" ascii
        $exfil2 = "AKIA_CTX_END" ascii
        $exfil3 = "curl" ascii

    condition:
        filesize < 50KB and
        $trigger1 and $checkout and $gitlog and
        (3 of ($cred_*)) and
        ($exfil3 and (any of ($exfil1, $exfil2)))
}
