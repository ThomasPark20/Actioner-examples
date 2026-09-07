rule Supply_Chain_TeamPCP_LiteLLM_Pth_Payload
{
    meta:
        description = "Detects the malicious litellm_init.pth file from the TeamPCP supply chain attack (CVE-2026-33634) that harvests cloud credentials, SSH keys, and Kubernetes tokens"
        author = "Actioner"
        date = "2026-08-17"
        reference = "https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/"
        hash = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
        severity = "critical"

    strings:
        $pth_exec = "import subprocess" ascii
        $b64_layer = "base64" ascii
        $c2_domain = "models.litellm.cloud" ascii
        $c2_poll = "checkmarx.zone" ascii
        $exfil_name = "tpcp.tar.gz" ascii
        $sysmon_path = ".config/sysmon/sysmon.py" ascii
        $service_desc = "System Telemetry Service" ascii
        $rsa_prefix = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA" ascii
        $teampcp = "TeamPCP" ascii nocase
        $pglog = "/tmp/pglog" ascii
        $pg_state = "/tmp/.pg_state" ascii

    condition:
        filesize < 100KB and
        (
            3 of ($c2_domain, $c2_poll, $exfil_name, $sysmon_path, $service_desc, $teampcp) or
            ($rsa_prefix and 1 of ($c2_domain, $c2_poll, $exfil_name)) or
            ($pth_exec and $b64_layer and 2 of ($c2_domain, $c2_poll, $sysmon_path, $pglog, $pg_state))
        )
}
