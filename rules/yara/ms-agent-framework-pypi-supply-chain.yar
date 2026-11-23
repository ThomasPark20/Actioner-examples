rule AgentFramework_PyPI_CredStealer
{
    meta:
        description = "Detects the credential stealer payload from malicious versions 1.26.1 and 1.26.2 of Microsoft's agent-framework PyPI package. Matches on distinctive module names, exfiltration URL components, User-Agent strings, anti-recursion marker, and targeted credential file patterns."
        author = "Actioner"
        date = "2026-11-23"
        reference1 = "https://research.jfrog.com/post/agent-framework-hijack/"
        reference2 = "https://github.com/advisories/GHSA-764m-3ppc-5m73"
        hash1 = "d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110"
        hash2 = "3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9"
        hash3 = "39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663"
        hash4 = "54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f"
        severity = "critical"

    strings:
        // Anti-recursion environment marker
        $env_marker    = "_AF_TEL" ascii

        // Exfiltration webhook UUID
        $webhook_uuid  = "d381fd80-ec62-42ad-8f5c-d1b15103c9bb" ascii

        // User-Agent strings
        $ua_v1         = "af-runtime-diagnostics/1" ascii
        $ua_v2         = "runtime-diagnostics/1" ascii

        // Module/file names unique to the payload
        $pth_v1        = "agent_framework_meta.pth" ascii
        $pth_v2        = "af_runtime_diag.pth" ascii

        // Persistence mechanism: .pth import line
        $pth_import_v1 = "import agent_framework_meta" ascii
        $pth_import_v2 = "import af_runtime_diag" ascii

        // Forking and daemonization pattern
        $fork_setsid   = "os.setsid()" ascii
        $fork_exit     = "os._exit(0)" ascii

        // Targeted credential paths
        $cred_azure    = ".azure/" ascii
        $cred_npmrc    = ".npmrc" ascii
        $cred_gitcred  = ".git-credentials" ascii
        $cred_docker   = ".docker/config.json" ascii
        $cred_netrc    = ".netrc" ascii

        // Azure IMDS and identity endpoint patterns
        $imds          = "169.254.169.254" ascii
        $oidc_audience = "api://AzureADTokenExchange" ascii

        // Azure DevOps token variables
        $ado_token     = "SYSTEM_ACCESSTOKEN" ascii

    condition:
        // High confidence: webhook UUID or both User-Agent variants
        $webhook_uuid
        or ($ua_v1 and $ua_v2)
        // High confidence: .pth file + corresponding module
        or ($pth_v1 and $pth_import_v1)
        or ($pth_v2 and $pth_import_v2)
        // Medium confidence: anti-recursion marker + fork/daemonize + credential targets
        or ($env_marker and ($fork_setsid or $fork_exit) and 2 of ($cred_azure, $cred_npmrc, $cred_gitcred, $cred_docker, $cred_netrc))
        // Medium confidence: OIDC audience + ADO tokens + IMDS
        or ($oidc_audience and $ado_token and $imds)
}

rule AgentFramework_PyPI_PthHook
{
    meta:
        description = "Detects .pth startup hook files dropped by malicious agent-framework versions. These 23-byte files contain a single import line that triggers the credential stealer on every Python interpreter start."
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://research.jfrog.com/post/agent-framework-hijack/"
        hash1 = "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e"
        hash2 = "325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93"
        severity = "high"

    strings:
        $import_v1 = "import agent_framework_meta" ascii
        $import_v2 = "import af_runtime_diag" ascii

    condition:
        filesize < 100 and any of them
}
