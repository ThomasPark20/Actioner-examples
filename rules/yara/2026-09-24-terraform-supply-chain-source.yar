rule Malware_Graphalgo_Terraform_Trojanized_Provider
{
    meta:
        description = "Detects trojanized Terraform provider source code containing the Graphalgo malware activation mechanism in the Docker container resource functions file"
        author = "Actioner"
        date = "2026-09-24"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"
        severity = "high"
        tlp = "WHITE"

    strings:
        // Malicious entry point file path
        $path1 = "internal/provider/resource_docker_container_funcs.go" ascii wide

        // Obfuscated malware function name pattern
        $func1 = "_ddb43801486d" ascii wide

        // Reconnaissance helper
        $recon1 = "helper.Keys()" ascii wide

        // Trigger hash (SHA256 of containerName + networkID)
        $trigger = "b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5" ascii wide nocase

        // Payload archive path within provider
        $archive = "examples/resources/docker_container/import-resource.sqlite3" ascii wide

    condition:
        filesize < 50MB and
        (
            $trigger or
            $func1 or
            ($path1 and $archive) or
            ($recon1 and 1 of ($path1, $archive))
        )
}
