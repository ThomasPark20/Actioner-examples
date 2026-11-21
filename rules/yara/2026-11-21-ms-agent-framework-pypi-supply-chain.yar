rule Supply_Chain_MS_Agent_Framework_PTH_Hook
{
    meta:
        description = "Detects malicious .pth startup hook files from compromised Microsoft agent-framework PyPI package (versions 1.26.1, 1.26.2)"
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth1 = "import agent_framework_meta" ascii
        $pth2 = "import af_runtime_diag" ascii

    condition:
        filesize < 1KB and
        any of ($pth*)
}

rule Supply_Chain_MS_Agent_Framework_Credential_Stealer
{
    meta:
        description = "Detects the credential stealer payload from the compromised Microsoft agent-framework PyPI package. Matches characteristic strings from the stealer module."
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $c2 = "webhook.site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb" ascii wide
        $azure1 = ".azure/" ascii
        $azure2 = "IDENTITY_ENDPOINT" ascii
        $azure3 = "MSI_ENDPOINT" ascii
        $azure4 = "169.254.169.254" ascii
        $oidc1 = "SYSTEM_ACCESSTOKEN" ascii
        $oidc2 = "SYSTEM_OIDCREQUESTURI" ascii
        $oidc3 = "AzureADTokenExchange" ascii
        $cred1 = ".npmrc" ascii
        $cred2 = "pip.conf" ascii
        $cred3 = ".netrc" ascii
        $cred4 = ".git-credentials" ascii
        $cred5 = ".docker/config.json" ascii
        $func1 = "zlib" ascii
        $func2 = "base64" ascii

    condition:
        filesize < 500KB and
        $c2 and
        (2 of ($azure*) or 2 of ($oidc*)) and
        2 of ($cred*) and
        all of ($func*)
}

rule Supply_Chain_MS_Agent_Framework_Malicious_Wheel
{
    meta:
        description = "Detects malicious Python wheel files from the compromised Microsoft agent-framework package by matching the combination of .pth hook filenames and exfiltration endpoint"
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $pth1 = "agent_framework_meta.pth" ascii
        $pth2 = "af_runtime_diag.pth" ascii
        $c2 = "webhook.site" ascii
        $ver1 = "1.26.1" ascii
        $ver2 = "1.26.2" ascii

    condition:
        $zip_magic at 0 and
        (1 of ($pth*)) and
        ($c2 or 1 of ($ver*))
}
