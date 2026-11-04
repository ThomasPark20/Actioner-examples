rule cpguard_malicious_script_strings
{
    meta:
        description = "Detects the specific malicious script filename from the cPGuard supply chain attack"
        author = "CTI Analyst"
        date = "2026-11-04"
        reference = "https://thehackernews.com/2026/11/cpguard-supply-chain-attack.html"
        severity = "critical"
        tlp = "white"

    strings:
        $script = "cpguard-v58812-i91511.sh" ascii wide
        $staging = "/var/tmp/.cpg91511" ascii wide
        $backdoor = "/var/tmp/.cpg91511_sh" ascii wide

    condition:
        any of them
}
