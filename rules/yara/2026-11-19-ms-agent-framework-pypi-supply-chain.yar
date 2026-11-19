rule Supply_Chain_AgentFramework_Credential_Stealer
{
    meta:
        description = "Detects the credential-stealing payload from compromised Microsoft agent-framework PyPI package versions 1.26.1 and 1.26.2"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        hash1 = "39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663"
        hash2 = "54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $enc_url = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi" ascii
        $guard_var = "_AF_TEL" ascii
        $ua1 = "af-runtime-diagnostics/1" ascii
        $ua2 = "runtime-diagnostics/1" ascii
        $setsid = "os.setsid()" ascii
        $proc_environ = "/proc/" ascii
        $proc_glob = "*/environ" ascii
        $imds = "169.254.169.254" ascii
        $oidc_aud = "api://AzureADTokenExchange" ascii
        $cred1 = ".git-credentials" ascii
        $cred2 = ".docker/config.json" ascii
        $cred3 = ".azure/" ascii
        $telemetry_desc = "Lightweight runtime diagnostics hook" ascii

    condition:
        filesize < 50KB and
        $enc_url and $guard_var and
        (1 of ($ua*)) and
        (2 of ($setsid, $proc_environ, $proc_glob, $imds, $oidc_aud)) and
        (1 of ($cred*) or $telemetry_desc)
}

rule Supply_Chain_AgentFramework_PTH_Hook
{
    meta:
        description = "Detects the malicious .pth startup hooks from compromised Microsoft agent-framework PyPI package versions 1.26.1 and 1.26.2"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised"
        hash1 = "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e"
        hash2 = "325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth1 = "import agent_framework_meta" ascii
        $pth2 = "import af_runtime_diag" ascii

    condition:
        filesize < 100 and
        (1 of them)
}
