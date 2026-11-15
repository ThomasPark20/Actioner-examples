rule PHP2Shell_Webshell_CheckPoint
{
    meta:
        description = "Detects PHP webshells deployed via PHP2Shell exploitation on Check Point Mobile Access portals"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html"
        severity = "high"

    strings:
        $upload_marker = "upload_progress_pwn" ascii
        $tpl_staging = "/tmp/.up.tpl" ascii
        $challenge = "challenge_render.tpl" ascii
        $php_exec1 = "system(" ascii
        $php_exec2 = "passthru(" ascii
        $php_exec3 = "shell_exec(" ascii
        $php_upload = "move_uploaded_file(" ascii

    condition:
        ($upload_marker or $tpl_staging or $challenge) and
        any of ($php_exec*, $php_upload)
}
