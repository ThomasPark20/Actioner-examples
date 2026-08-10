rule Exploit_Certighost_CVE_2026_54121
{
    meta:
        description = "Detects the Certighost PoC exploit tool (certighost.py) for CVE-2026-54121 AD CS DC impersonation"
        author = "Actioner"
        date = "2026-07-26"
        reference = "https://github.com/aniqfakhrul/CVE-2026-54121"
        severity = "critical"

    strings:
        $tool_name = "certighost" ascii nocase
        $cve = "CVE-2026-54121" ascii
        $attr_cdc = "cdc" ascii fullword
        $attr_rmd = "rmd" ascii fullword
        $arg_dcip = "--dc-ip" ascii
        $arg_compname = "--computer-name" ascii
        $arg_listener = "--listener" ascii
        $ghost_prefix = "GHOST" ascii
        $chase_flag = "EDITF_ENABLECHASECLIENTDC" ascii
        $pkinit = "PKINIT" ascii nocase

    condition:
        filesize < 1MB and
        (
            ($tool_name and $attr_cdc and $attr_rmd) or
            ($cve and 2 of ($arg_dcip, $arg_compname, $arg_listener)) or
            ($tool_name and $ghost_prefix and 1 of ($arg_dcip, $arg_compname, $arg_listener)) or
            ($chase_flag and $tool_name) or
            ($pkinit and $tool_name and $attr_cdc)
        )
}
