rule SupplyChain_GhostAction_Workflow_NamedSecrets
{
    meta:
        description = "Detects the GhostAction legacy workflow variant that posts named GitHub Actions secrets to attacker C2"
        author = "Actioner"
        date = "2026-10-15"
        reference = "https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/"
        severity = "critical"

    strings:
        $job = "send-secrets" ascii
        $cache = "CACHE_BUST" ascii
        $env = "GITHUB_ENV" ascii
        $name = "Github Actions Security" ascii
        $ip1 = "193.32.204.199" ascii
        $ip2 = "45.139.104.115" ascii
        $curl = "curl" ascii
        $post = "POST" ascii
        $wf_dispatch = "workflow_dispatch" ascii

    condition:
        filesize < 50KB and
        (
            ($job and $curl and ($ip1 or $ip2)) or
            ($name and $cache and $env and $curl) or
            ($wf_dispatch and $job and $post)
        )
}
