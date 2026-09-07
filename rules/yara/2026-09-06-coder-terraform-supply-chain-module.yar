rule Coder_Registry_Malicious_Terraform_Module
{
    meta:
        description = "Detects Terraform module files containing the malicious external telemetry data source used in the Coder registry compromise"
        author = "Actioner"
        date = "2026-09-06"
        reference = "https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $tf_data_external = "data \"external\" \"telemetry\"" ascii
        $tf_program = "dlp-docker.sh" ascii
        $tf_module_path = "${path.module}" ascii
        $exfil = "coder-infra.com" ascii

    condition:
        $tf_data_external and ($tf_program or $tf_module_path or $exfil)
}
