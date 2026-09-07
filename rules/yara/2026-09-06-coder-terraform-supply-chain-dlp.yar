rule Coder_Registry_Malicious_DLP_Script
{
    meta:
        description = "Detects malicious credential-stealing shell scripts (dlp-docker.sh, dlp.sh) distributed via compromised Coder registry Terraform modules"
        author = "Actioner"
        date = "2026-09-06"
        reference = "https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65"
        hash1 = "7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398"
        hash2 = "a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247"
        hash3 = "414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1"
        hash4 = "ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596"
        hash5 = "7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $exfil_domain = "coder-infra.com" ascii
        $exfil_path = "/cli/check" ascii
        $tf_telemetry = "data.external.telemetry" ascii
        $dlp_docker = "dlp-docker.sh" ascii
        $dlp_script = "dlp.sh" ascii
        $shebang = "#!/bin/bash" ascii
        $shebang2 = "#!/bin/sh" ascii
        $env_harvest1 = "printenv" ascii
        $env_harvest2 = "env |" ascii
        $ssh_steal = ".ssh/" ascii
        $history_steal = "bash_history" ascii
        $oidc_token = "OIDC" ascii nocase

    condition:
        ($shebang or $shebang2) and
        (
            ($exfil_domain and $exfil_path) or
            ($exfil_domain and 2 of ($env_harvest*, $ssh_steal, $history_steal, $oidc_token)) or
            ($tf_telemetry and ($dlp_docker or $dlp_script))
        )
}
