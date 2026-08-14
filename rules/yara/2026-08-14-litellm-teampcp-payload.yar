rule TeamPCP_LiteLLM_Malicious_PTH_Payload
{
    meta:
        description = "Detects the malicious litellm_init.pth file or related TeamPCP credential-stealing payload from the LiteLLM supply chain attack (CVE-2026-33634)"
        author = "Actioner"
        date = "2026-08-14"
        reference = "https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/"
        hash_pth = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
        hash_proxy = "a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b"
        hash_sysmon = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"

    strings:
        // Campaign-specific indicators (unique to TeamPCP)
        $specific_pth = "litellm_init.pth" ascii
        $specific_exfil = "models.litellm.cloud" ascii
        $specific_c2 = "checkmarx.zone" ascii
        $specific_tpcp = "tpcp.tar.gz" ascii
        $specific_team = "TeamPCP" ascii nocase
        $specific_rsa = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvahaZDo8mucujrT15ry+" ascii
        $specific_xfn = "X-Filename: tpcp.tar.gz" ascii
        $specific_sysmon = ".config/sysmon/sysmon.py" ascii

        // Generic indicators (may appear in legitimate AI/ML software)
        $generic_svc = "sysmon.service" ascii
        $generic_pgstate = "/tmp/.pg_state" ascii
        $generic_pglog = "/tmp/pglog" ascii
        $generic_openai = "OPENAI_API_KEY" ascii
        $generic_anthropic = "ANTHROPIC_API_KEY" ascii

    condition:
        1 of ($specific_*) and 3 of them
}

rule TeamPCP_LiteLLM_Sysmon_Backdoor
{
    meta:
        description = "Detects the sysmon.py persistent backdoor deployed by TeamPCP after LiteLLM compromise"
        author = "Actioner"
        date = "2026-08-14"
        reference = "https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html"
        hash = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"

    strings:
        $c2_poll = "checkmarx.zone/raw" ascii
        $kill_switch = "youtube" ascii
        $sysmon_dir = ".config/sysmon" ascii
        $systemd_unit = "System Telemetry Service" ascii
        $pg_state = ".pg_state" ascii

    condition:
        ($c2_poll and $kill_switch) or ($systemd_unit and $sysmon_dir) or ($c2_poll and $pg_state)
}
