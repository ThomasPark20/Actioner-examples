rule PHP2Shell_Webshell_change_password : webshell php2shell
{
    meta:
        description = "Detects small PHP webshells planted at change_password.php, consistent with the PHP2Shell campaign. The campaign used a 103-byte PHP root webshell."
        author = "Actioner"
        date = "2026-10-30"
        reference = "https://dreamgroup.com/blog/chained-php2shell-exploit-roots-25-servers"
        severity = "critical"

    strings:
        $php_open = "<?php" ascii nocase
        $exec1 = "system(" ascii nocase
        $exec2 = "exec(" ascii nocase
        $exec3 = "passthru(" ascii nocase
        $exec4 = "shell_exec(" ascii nocase
        $exec5 = "popen(" ascii nocase
        $exec6 = "proc_open(" ascii nocase
        $exec7 = "eval(" ascii nocase
        $input1 = "$_GET" ascii
        $input2 = "$_POST" ascii
        $input3 = "$_REQUEST" ascii
        $input4 = "$_COOKIE" ascii

    condition:
        $php_open and
        filesize < 300 and
        1 of ($exec*) and
        1 of ($input*)
}

rule PHP2Shell_Panops_Persistence : persistence php2shell
{
    meta:
        description = "Detects files in the .panops persistence directory used by the PHP2Shell campaign on compromised PAN-OS devices"
        author = "Actioner"
        date = "2026-10-30"
        reference = "https://dreamgroup.com/blog/chained-php2shell-exploit-roots-25-servers"
        severity = "critical"

    strings:
        $path1 = "/usr/local/lib/.panops" ascii
        $path2 = ".panops/" ascii
        $sh = "#!/bin/" ascii

    condition:
        $sh and 1 of ($path*)
}
