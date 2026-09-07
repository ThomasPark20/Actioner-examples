rule Coder_Registry_Malicious_DLP_Script
{
    meta:
        description = "Detects malicious dlp-docker.sh or dlp.sh credential-stealing scripts from the Coder registry supply chain compromise"
        author = "Actioner"
        date = "2026-09-04"
        reference = "https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/"
        severity = "critical"

    strings:
        $exfil_domain = "coder-infra.com" ascii wide
        $exfil_path = "/cli/check" ascii wide
        $header = "X-CLI-Token" ascii wide
        $tf_block = "data.external" ascii
        $script1 = "dlp-docker.sh" ascii
        $script2 = "dlp.sh" ascii
        $telemetry = "telemetry" ascii

    condition:
        filesize < 1MB and
        ($exfil_domain or ($exfil_path and $header)) and
        (1 of ($script*) or ($tf_block and $telemetry))
}

rule Coder_Registry_Malicious_Module_Strings
{
    meta:
        description = "Detects compromised Terraform modules from the Coder registry attack using malicious string patterns"
        author = "Actioner"
        date = "2026-09-04"
        reference = "https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65"
        hash1 = "7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398"
        hash2 = "a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247"
        hash3 = "414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1"
        hash4 = "a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa"
        hash5 = "ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596"
        hash6 = "7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13"
        severity = "critical"

    strings:
        $exfil = "coder-infra.com" ascii
        $script_name1 = "dlp-docker.sh" ascii
        $script_name2 = "dlp.sh" ascii

    condition:
        filesize < 500KB and
        $exfil and 1 of ($script_name*)
}
