rule Exploit_WP2Shell_Webshell_Plugin
{
    meta:
        description = "Detects wp2shell webshell plugin deployed via CVE-2026-63030 exploitation, identified by response markers and command interface patterns"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://www.cyberkendra.com/2026/07/wp2shell-guide.html"
        reference2 = "https://github.com/InstaWP/wp2shell-scan"
        severity = "critical"

    strings:
        $marker_start = "WP2SHELL_OUT_START" ascii
        $marker_end = "WP2SHELL_OUT_END" ascii
        $header = "Author: WordPress.org Community" ascii
        $param_tok = "$_GET['tok']" ascii
        $param_c = "$_GET['c']" ascii
        $param_rm = "$_GET['rm']" ascii
        $eval1 = "eval(" ascii
        $eval2 = "shell_exec(" ascii
        $eval3 = "system(" ascii
        $eval4 = "passthru(" ascii
        $eval5 = "base64_decode(" ascii

    condition:
        filesize < 10KB and
        (
            ($marker_start and $marker_end) or
            ($header and 2 of ($param_*)) or
            ($header and 2 of ($eval*) and 1 of ($param_*))
        )
}

rule Exploit_WP2Shell_CMSmap_Webshell
{
    meta:
        description = "Detects the larger CMSmap-style obfuscated webshell (approx 150KB) observed in wp2shell post-exploitation campaigns"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137"
        severity = "high"

    strings:
        $gzip = "gzinflate(" ascii
        $eval = "eval(" ascii
        $b64 = "base64_decode(" ascii
        $hex_decode = "hex2bin(" ascii
        $plugin_header = "Plugin Name:" ascii
        $fake_author = "Author: WordPress.org" ascii
        $cmd1 = "shell_exec" ascii
        $cmd2 = "proc_open" ascii
        $cmd3 = "passthru" ascii

    condition:
        filesize > 50KB and filesize < 300KB and
        $plugin_header and $fake_author and
        $eval and ($gzip or $b64 or $hex_decode) and
        1 of ($cmd*)
}
