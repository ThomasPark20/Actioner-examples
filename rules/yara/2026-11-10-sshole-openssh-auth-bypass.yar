rule SSHole_TACAgent_PythonImplant
{
    meta:
        description = "Detects the TAC agent Python implant used in CVE-2026-123158 post-exploitation"
        author = "Actioner CTI"
        date = "2026-11-10"
        reference = "https://sshole.events.greynoise.io"
        hash = "55e6384f6d1648be9b48fb899e46623e9c05eb0df2cbf95f6701680d4e7cbc2a"
        severity = "critical"

    strings:
        $ua = "TAC-Agent/1.0" ascii
        $c2_path1 = "/agent/register" ascii
        $c2_path2 = "/agent/poll" ascii
        $c2_path3 = "/agent/result-object" ascii
        $c2_path4 = "/agent/results" ascii
        $c2_path5 = "/agent/file-object" ascii
        $c2_path6 = "/agent/update-artifacts/" ascii
        $header1 = "X-TAC-Poll-Interval" ascii
        $header2 = "X-TAC-Agent-Capabilities" ascii
        $header3 = "X-TAC-Agent-Version" ascii
        $header4 = "X-TAC-Executor-Info" ascii
        $domain = "tac.vpnla.org" ascii
        $version = "v0.1.1" ascii
        $executor = "__executor_worker__" ascii

    condition:
        filesize < 200KB and
        (
            ($ua and any of ($c2_path*)) or
            ($domain and any of ($header*)) or
            (3 of ($c2_path*) and any of ($header*)) or
            ($executor and $ua) or
            ($version and $domain and $ua)
        )
}
