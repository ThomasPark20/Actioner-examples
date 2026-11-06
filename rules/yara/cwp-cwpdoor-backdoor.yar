rule Backdoor_CWP_CWPDoor_Strings
{
    meta:
        description = "Detects the CWP (Control Web Panel) backdoored cwpsrv binary by characteristic strings: the X-Ngx-Integrity custom header prefix and the ngx_http_integrity_helper Unix socket name. Both are unique to the backdoor and not present in legitimate CWP builds."
        author = "Actioner"
        date = "2026-11-06"
        reference = "https://blog.xlab.qianxin.com/cwpdoor-the-invisible-backdoor-living-inside-control-web-panel/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $header = "X-Ngx-Integrity" ascii
        $socket = "ngx_http_integrity_helper" ascii
        $elf    = { 7F 45 4C 46 }

    condition:
        $elf at 0 and
        filesize < 20MB and
        $header and
        $socket
}

rule Backdoor_CWP_CWPDoor_Installer
{
    meta:
        description = "Detects the cwpsrv_update.sh installer script used to deploy the CWP backdoor. Matches on the combination of the download server IP, backdoored binary filenames, and shell script markers."
        author = "Actioner"
        date = "2026-11-06"
        reference = "https://blog.xlab.qianxin.com/cwpdoor-the-invisible-backdoor-living-inside-control-web-panel/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $ip       = "136.0.141.71" ascii
        $path1    = "/static/cwpsrv_1.15.10" ascii
        $path2    = "/static/cwpsrv_1.24.0" ascii
        $path3    = "/static/cwpsrv_update.sh" ascii
        $target   = "/usr/local/cwpsrv/bin/cwpsrv" ascii
        $shebang  = "#!/bin/" ascii

    condition:
        $shebang at 0 and
        filesize < 1MB and
        $ip and
        $target and
        1 of ($path*)
}
