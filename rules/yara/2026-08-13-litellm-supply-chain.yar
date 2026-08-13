rule Supply_Chain_LiteLLM_TeamPCP_PTH_Backdoor
{
    meta:
        description = "Detects the malicious litellm_init.pth file used by TeamPCP in the LiteLLM supply chain attack (CVE-2026-33634)"
        author = "Actioner"
        date = "2026-08-13"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
        severity = "critical"

    strings:
        $pth_exec = "subprocess.Popen" ascii
        $b64_import = "base64" ascii
        $tpcp_var = "tpcp" ascii
        $session_key_enc = "session.key.enc" ascii
        $crypto1 = "AES" ascii
        $crypto2 = "RSA" ascii
        $crypto3 = "OAEP" ascii
        $c2_domain1 = "models.litellm.cloud" ascii
        $c2_domain2 = "checkmarx.zone" ascii
        $exfil_archive = "tpcp.tar.gz" ascii
        $sysmon_path = ".config/sysmon/sysmon.py" ascii
        $k8s_lateral = "node-setup-" ascii

    condition:
        filesize < 100KB and
        (
            (2 of ($c2_domain*, $exfil_archive, $sysmon_path, $k8s_lateral)) or
            ($pth_exec and $b64_import and $tpcp_var and 1 of ($crypto*)) or
            ($pth_exec and $b64_import and $session_key_enc)
        )
}

rule Supply_Chain_LiteLLM_TeamPCP_Sysmon_Backdoor
{
    meta:
        description = "Detects the sysmon.py backdoor script used by TeamPCP for persistent C2 polling"
        author = "Actioner"
        date = "2026-08-13"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"
        severity = "critical"

    strings:
        $c2_poll = "checkmarx.zone" ascii
        $c2_path = "/raw" ascii
        $pglog = "/tmp/pglog" ascii
        $pg_state = "/tmp/.pg_state" ascii
        $sysmon_svc = "sysmon.service" ascii

    condition:
        filesize < 50KB and
        $c2_poll and
        2 of ($c2_path, $pglog, $pg_state, $sysmon_svc)
}
