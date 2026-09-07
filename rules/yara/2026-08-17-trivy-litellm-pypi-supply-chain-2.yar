rule Supply_Chain_TeamPCP_Sysmon_Backdoor
{
    meta:
        description = "Detects the TeamPCP sysmon.py persistence backdoor that polls checkmarx.zone for follow-on payloads and masquerades as System Telemetry Service"
        author = "Actioner"
        date = "2026-08-17"
        reference = "https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/"
        hash = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"
        severity = "critical"

    strings:
        $c2_poll = "checkmarx.zone" ascii
        $dl_path = "/tmp/pglog" ascii
        $state_file = "/tmp/.pg_state" ascii
        $sysmon_svc = "System Telemetry Service" ascii
        $kill_switch = "youtube" ascii
        $tpcp = "tpcp" ascii

    condition:
        filesize < 50KB and
        (
            ($c2_poll and 1 of ($dl_path, $state_file, $sysmon_svc)) or
            ($c2_poll and $kill_switch and $tpcp)
        )
}
