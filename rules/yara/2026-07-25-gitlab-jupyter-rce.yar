/*
    GitLab RCE via Oj JSON Parser Memory Corruption (CVE-2026-54592, CVE-2026-54500)
    YARA rules for detecting malicious Jupyter notebook payloads
    Author: Actioner
    Date: 2026-07-25
    Reference: https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities
*/

rule Exploit_GitLab_Malicious_Jupyter_Notebook_Oj_RCE
{
    meta:
        description = "Detects malicious Jupyter notebook (.ipynb) files crafted to exploit CVE-2026-54592 and CVE-2026-54500 in the Oj JSON parser via GitLab notebook diff rendering. The exploit uses deeply nested JSON arrays (2000+ levels) to overflow the parser nesting stack, and oversized object keys (65000+ bytes) to trigger signed integer truncation for heap pointer disclosure."
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities"
        severity = "high"

    strings:
        $nb_cells = "\"cells\"" ascii
        $nb_meta = "\"metadata\"" ascii
        $nb_nbformat = "\"nbformat\"" ascii

        $deep_nest_array = /\[{500,}/ ascii
        $deep_nest_object = /\{{500,}/ ascii

        $long_key_a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
        $long_key_b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ascii

        $large_number = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" ascii

        $cmd_touch = "touch /tmp/" ascii
        $cmd_curl = "curl " ascii
        $cmd_wget = "wget " ascii
        $cmd_bash = "/bin/bash" ascii
        $cmd_sh = "/bin/sh" ascii
        $cmd_nc = "nc -e" ascii
        $cmd_python = "python -c" ascii
        $cmd_id = { 69 64 00 }

    condition:
        filesize < 50MB and
        2 of ($nb_*) and
        (
            ($deep_nest_array or $deep_nest_object) or
            ($long_key_a or $long_key_b) or
            ($large_number and 1 of ($cmd_*))
        )
}

rule Exploit_GitLab_Notebook_Heap_Spray_Payload
{
    meta:
        description = "Detects Jupyter notebook payloads containing binary data patterns consistent with the GitLab Oj RCE heap spray and gadget chain. The exploit embeds crafted Float immediates and Fixnum values that encode ROP gadget addresses for redirecting execution to system()."
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities"
        severity = "high"

    strings:
        $nb_cells = "\"cells\"" ascii
        $nb_type = "\"cell_type\"" ascii

        $float_neg = "-1e45" ascii
        $float_neg2 = "-1e44" ascii
        $float_neg3 = "-1e46" ascii

        $array_fill = "null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null" ascii

        $deep_brackets = "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[" ascii

    condition:
        filesize < 50MB and
        1 of ($nb_*) and
        (
            1 of ($float_neg*) and
            ($array_fill or $deep_brackets)
        )
}
