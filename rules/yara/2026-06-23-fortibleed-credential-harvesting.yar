rule FortiBleed_FortigateSniffer_Tool
{
    meta:
        description = "Detects the FortigateSniffer Golang-based tool used in the FortiBleed campaign to passively capture authentication traffic from compromised FortiGate devices across 24 protocols"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html"
        severity = "critical"

    strings:
        $tool1 = "FortigateSniffer" ascii wide nocase
        $tool2 = "fortisniffer" ascii wide nocase
        $cmd1 = "diagnose sniffer packet" ascii wide
        $cmd2 = "diag sniffer packet" ascii wide
        $proto1 = "RADIUS" ascii
        $proto2 = "Kerberos" ascii
        $proto3 = "NTLM" ascii
        $proto4 = "LDAP" ascii
        $proto5 = "MSSQL" ascii
        $proto6 = "RDP" ascii
        $go1 = "go.buildid" ascii
        $go2 = "runtime.main" ascii
        $forti1 = "FortiOS" ascii wide
        $forti2 = "FortiGate" ascii wide
        $forti3 = "fortigate" ascii wide

    condition:
        (any of ($tool*)) or
        (any of ($cmd*) and 3 of ($proto*)) or
        (any of ($go*) and any of ($cmd*) and any of ($forti*))
}

rule FortiBleed_Campaign_Wordlist
{
    meta:
        description = "Detects FortiBleed campaign wordlists and credential databases used for brute-forcing FortiGate admin accounts with curated naming conventions"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://socradar.io/blog/dismantling-fortibleed/"
        severity = "high"

    strings:
        $h1 = "forticloud" ascii nocase
        $h2 = "fortiuser" ascii nocase
        $h3 = "fortinet-support" ascii nocase
        $h4 = "fortinet-tech-support" ascii nocase
        $p1 = "admin" ascii
        $p2 = "password" ascii nocase
        $ctx1 = "FortiGate" ascii wide nocase
        $ctx2 = "FortiOS" ascii wide nocase
        $ctx3 = "SSL-VPN" ascii wide nocase

    condition:
        filesize < 100MB and
        3 of ($h*) and
        any of ($p*) and
        any of ($ctx*)
}

rule FortiBleed_Recon_Tool
{
    meta:
        description = "Detects FortiBleed campaign reconnaissance tools such as FortiProbe-fast and Shodan_Recon used for internet-wide scanning to identify FortiGate devices"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://securityaffairs.com/194004/hacking/fortibleed-the-most-detailed-breakdown-yet-of-an-active-russian-credential-harvesting-operation.html"
        severity = "high"

    strings:
        $tool1 = "FortiProbe" ascii wide nocase
        $tool2 = "Shodan_Recon" ascii wide
        $tool3 = "FortiProbe-fast" ascii wide
        $scan1 = "masscan" ascii nocase
        $forti1 = "FortiGate" ascii wide
        $forti2 = "FortiOS" ascii wide
        $go1 = "go.buildid" ascii
        $go2 = "runtime.main" ascii

    condition:
        (any of ($tool*)) or
        (any of ($go*) and $scan1 and any of ($forti*))
}
