rule SupplyChain_TeamPCP_LiteLLM_PTH_Loader
{
    meta:
        description = "Detects the malicious litellm_init.pth file used for Python startup persistence in the TeamPCP supply chain attack (CVE-2026-33634)"
        author = "Actioner"
        date = "2026-08-15"
        reference = "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth_name = "litellm_init" ascii
        $c2_1 = "models.litellm.cloud" ascii wide
        $c2_2 = "checkmarx.zone" ascii wide
        $c2_3 = "scan.aquasecurtiy.org" ascii wide
        $env_1 = "OPENAI_API_KEY" ascii
        $env_2 = "ANTHROPIC_API_KEY" ascii
        $env_3 = "AWS_SECRET_ACCESS_KEY" ascii

    condition:
        filesize < 500KB and
        (($pth_name and 1 of ($c2_*)) or
        (2 of ($c2_*) and 1 of ($env_*)))
}

rule SupplyChain_TeamPCP_Trivy_Infostealer
{
    meta:
        description = "Detects the TeamPCP infostealer payload injected into compromised Trivy GitHub Actions (CVE-2026-33634)"
        author = "Actioner"
        date = "2026-08-15"
        reference = "https://github.com/advisories/GHSA-69fq-xp46-6x23"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $c2 = "scan.aquasecurtiy.org" ascii wide
        $repo_1 = "tpcp-docs" ascii
        $repo_2 = "docs-tpcp" ascii
        $proc_mem = "/proc/" ascii
        $data_tag = "data-" ascii
        $skip_validate = "--skip=validate" ascii

    condition:
        filesize < 5MB and
        ($c2 or (1 of ($repo_*) and $data_tag)) and
        ($proc_mem or $skip_validate)
}
