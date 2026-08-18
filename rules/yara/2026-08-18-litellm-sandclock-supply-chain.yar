rule Supply_Chain_SANDCLOCK_LiteLLM_PTH
{
    meta:
        description = "Detects the SANDCLOCK credential-stealer .pth file dropped by malicious LiteLLM 1.82.7/1.82.8 packages. Keys on double base64-encoded launcher, campaign markers, and exfiltration domain."
        author = "Actioner"
        date = "2026-08-18"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth_exec = "import subprocess" ascii
        $b64_decode = "base64" ascii
        $campaign_marker1 = "tpcp" ascii nocase
        $exfil_domain = "models.litellm.cloud" ascii
        $c2_domain = "checkmarx.zone" ascii
        $alt_exfil = "scan.aquasecurtiy.org" ascii
        $persistence_path = ".config/sysmon/sysmon.py" ascii
        $service_name = "sysmon.service" ascii
        $pg_state = "/tmp/.pg_state" ascii
        $pglog = "/tmp/pglog" ascii
        $rsa_marker = "BEGIN PUBLIC KEY" ascii
        $aes_key_gen = "openssl rand" ascii
        $tar_bundle = "tpcp.tar.gz" ascii
        $proc_mem = "/proc/" ascii
        $mem_path = "/mem" ascii

    condition:
        filesize < 100KB and
        $pth_exec and $b64_decode and
        (
            ($exfil_domain or $c2_domain or $alt_exfil) or
            ($campaign_marker1 and $tar_bundle) or
            ($persistence_path and $service_name) or
            (4 of ($pg_state, $pglog, $rsa_marker, $aes_key_gen, $proc_mem, $mem_path))
        )
}

rule Supply_Chain_SANDCLOCK_Sysmon_Backdoor
{
    meta:
        description = "Detects the SANDCLOCK persistence backdoor (sysmon.py) that polls checkmarx.zone for follow-on payloads with a YouTube-based kill switch."
        author = "Actioner"
        date = "2026-08-18"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"
        severity = "high"
        tlp = "WHITE"

    strings:
        $c2_poll = "checkmarx.zone" ascii
        $raw_endpoint = "/raw" ascii
        $kill_switch = "youtube" ascii
        $pglog = "/tmp/pglog" ascii
        $pg_state = "/tmp/.pg_state" ascii
        $chmod = "chmod" ascii
        $start_new_session = "start_new_session" ascii
        $persistence_sysmon = "sysmon.py" ascii

    condition:
        filesize < 50KB and
        $c2_poll and
        (
            ($raw_endpoint and $kill_switch) or
            ($pglog and $pg_state) or
            ($chmod and $start_new_session and $persistence_sysmon)
        )
}
