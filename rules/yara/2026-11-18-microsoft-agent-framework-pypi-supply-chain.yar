rule Supply_Chain_AgentFramework_PTH_Hook
{
    meta:
        description = "Detects malicious .pth startup hook files from compromised agent-framework 1.26.1/1.26.2"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        severity = "critical"
        hash_pth_v1 = "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e"
        hash_pth_v2 = "325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93"

    strings:
        $pth_v1 = "import agent_framework_meta" ascii
        $pth_v2 = "import af_runtime_diag" ascii

    condition:
        filesize < 512 and
        any of ($pth_*)
}

rule Supply_Chain_AgentFramework_Credential_Stealer_v1
{
    meta:
        description = "Detects the _telemetry.py credential stealer module from compromised agent-framework 1.26.1"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        severity = "critical"
        hash = "39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663"

    strings:
        $enc_url = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi" ascii
        $ua1 = "af-runtime-diagnostics/1" ascii
        $reentry = "_AF_TEL" ascii
        $docstring = "Lightweight runtime diagnostics hook" ascii
        $func_start = "_start" ascii
        $func_run = "_run" ascii
        $proc_env = "/proc/" ascii
        $environ = "/environ" ascii
        $telemetry_param = "?t=telemetry" ascii
        $setsid = "os.setsid" ascii
        $azure_dir = ".azure" ascii
        $git_creds = ".git-credentials" ascii
        $npmrc = ".npmrc" ascii
        $credentials_file = ".credentials" ascii

    condition:
        filesize < 100KB and
        $enc_url and
        3 of ($ua1, $reentry, $docstring, $func_start, $func_run, $telemetry_param, $setsid) and
        2 of ($proc_env, $environ, $azure_dir, $git_creds, $npmrc, $credentials_file)
}

rule Supply_Chain_AgentFramework_Credential_Stealer_v2
{
    meta:
        description = "Detects the af_runtime_diag.py credential stealer module from compromised agent-framework 1.26.2"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        severity = "critical"
        hash = "54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f"

    strings:
        $enc_url = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi" ascii
        $ua2 = "runtime-diagnostics/1" ascii
        $reentry = "_AF_TEL" ascii
        $setsid = "os.setsid" ascii
        $actions_oidc = "ACTIONS_ID_TOKEN_REQUEST_URL" ascii
        $runner_path = "/home/runner/work/_temp/" ascii
        $runner_azure = "/home/runner/.azure/" ascii
        $oidc_audience = "api://AzureADTokenExchange" ascii
        $mgmt_audience = "https://management.azure.com/" ascii
        $telemetry_param = "?t=telemetry" ascii
        $proc_env = "/proc/" ascii

    condition:
        filesize < 100KB and
        $enc_url and
        2 of ($ua2, $reentry, $setsid, $telemetry_param) and
        2 of ($actions_oidc, $runner_path, $runner_azure, $oidc_audience, $mgmt_audience, $proc_env)
}

rule Supply_Chain_AgentFramework_Malicious_Wheel
{
    meta:
        description = "Detects compromised agent-framework wheel files (1.26.1 or 1.26.2) by embedded stealer artifacts"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        severity = "critical"
        hash_v1 = "d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110"
        hash_v2 = "3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9"

    strings:
        $enc_url = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi" ascii
        $pth_v1 = "agent_framework_meta.pth" ascii
        $pth_v2 = "af_runtime_diag.pth" ascii
        $ua1 = "af-runtime-diagnostics/1" ascii
        $ua2 = "runtime-diagnostics/1" ascii
        $telemetry = "_telemetry.py" ascii
        $diag = "af_runtime_diag.py" ascii

    condition:
        filesize < 5MB and
        $enc_url and
        (1 of ($pth_*) or 1 of ($ua*)) and
        (1 of ($telemetry, $diag))
}
