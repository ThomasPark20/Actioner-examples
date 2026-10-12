rule SupplyChain_GhostAction_Malicious_Workflow
{
    meta:
        description = "Detects GhostAction malicious GitHub Actions workflow files that steal credentials from CI/CD runners and git history"
        author = "Actioner"
        date = "2026-10-12"
        reference = "https://www.stepsecurity.io/blog/ghostaction-returns"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_ip = "193.32.204.199" ascii
        $marker1 = "AKIA_CTX_START" ascii
        $marker2 = "AKIA_CTX_END" ascii
        $param_monami = "c=monami" ascii
        $param_new = "c=new" ascii
        $fetch_depth = "fetch-depth: 0" ascii
        $git_sweep = "git log -p --all" ascii
        $wf_name1 = "Security Audit" ascii
        $wf_name2 = "Github Actions Security" ascii
        $step_name = "Prepare Cache Busting" ascii
        $job_name = "send-secrets" ascii
        $curl_post = "curl -s" ascii
        $data_binary = "--data-binary" ascii

    condition:
        filesize < 50KB and
        (
            (
                $c2_ip and
                2 of ($marker1, $marker2, $param_monami, $param_new)
            ) or
            (
                $fetch_depth and
                $git_sweep and
                1 of ($wf_name1, $wf_name2, $step_name, $job_name) and
                ($curl_post or $data_binary)
            )
        )
}
