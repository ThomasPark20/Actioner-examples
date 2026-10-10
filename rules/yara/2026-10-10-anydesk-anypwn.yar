rule AnyPwn_Exploit_Script
{
    meta:
        description = "Detects the AnyPwn exploit tool or variants targeting AnyDesk Linux pre-auth heap buffer overflow"
        author = "Actioner"
        date = "2026-10-10"
        reference = "https://github.com/v12-security/pocs/tree/main/anydesk"
        reference2 = "https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html"
        severity = "critical"

    strings:
        $anypwn_name = "AnyPwn" ascii nocase
        $anydesk_target = "anydesk" ascii nocase
        $port_7070 = "7070" ascii
        $heap_spray = "spray" ascii nocase
        $mode5 = "mode-5" ascii nocase
        $mode5_alt = "mode_5" ascii nocase
        $overflow_val1 = { F0 FF FF FF }
        $overflow_val2 = { FF FF FF F0 }
        $rop_chain = "ROP" ascii nocase
        $system_call = "system(" ascii
        $system_plt = "system@plt" ascii
        $vuln_version = "8.0.2" ascii

    condition:
        ($anypwn_name) or
        (3 of ($anydesk_target, $port_7070, $heap_spray, $mode5, $mode5_alt, $rop_chain, $system_call, $system_plt, $vuln_version)) or
        (($overflow_val1 or $overflow_val2) and $anydesk_target)
}
