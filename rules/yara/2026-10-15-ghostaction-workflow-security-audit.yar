rule SupplyChain_GhostAction_Workflow_SecurityAudit
{
    meta:
        description = "Detects GhostAction malicious GitHub Actions workflow files that steal credentials from repositories"
        author = "Actioner"
        date = "2026-10-15"
        reference = "https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/"
        severity = "critical"

    strings:
        $name1 = "Security Audit" ascii
        $name2 = "Github Actions Security" ascii
        $name3 = "Security Check" ascii

        $trigger = "workflow_dispatch" ascii

        $checkout = "fetch-depth: 0" ascii

        $grep1 = "AKIA" ascii
        $grep2 = "ghp_" ascii
        $grep3 = "github_pat_" ascii
        $grep4 = "sk-ant-" ascii
        $grep5 = "sk-proj-" ascii
        $grep6 = "glpat-" ascii

        $exfil_ip = "193.32.204.199" ascii
        $exfil_curl = "curl" ascii

        $marker1 = "AKIA_CTX_START" ascii
        $marker2 = "AKIA_CTX_END" ascii

        $gitlog = "git log -p --all" ascii

    condition:
        filesize < 50KB and
        1 of ($name*) and
        $trigger and
        (
            ($checkout and 2 of ($grep*)) or
            ($exfil_ip and $exfil_curl) or
            (1 of ($marker*)) or
            ($gitlog and 1 of ($grep*))
        )
}
