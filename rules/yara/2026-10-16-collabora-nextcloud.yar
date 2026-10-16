rule Collabora_CODE_WebShell_CVE_2026_110447 {
    meta:
        description = "Detects the PHP web shell dropped during exploitation of CVE-2026-110447 in the Collabora Online Built-in CODE Server for Nextcloud"
        author = "Actioner"
        date = "2026-10-16"
        reference = "https://github.com/CollaboraOnline/richdocumentscode/issues/354"
        hash = "4b9fbd0663fbfd6028fc216ed18e0d6ef3ae498a7fdc97083e4b0ce3cec40562"
        severity = "critical"

    strings:
        $exact_shell = "<?php $c=$_GET['c']??'id'; echo shell_exec($c.' 2>&1');" ascii
        $var_get = "$_GET['c']" ascii
        $shell_exec = "shell_exec(" ascii
        $default_id = "??'id'" ascii
        $stderr_redirect = "2>&1" ascii

    condition:
        $exact_shell or
        (filesize < 200 and $var_get and $shell_exec and $default_id) or
        (filesize < 200 and $shell_exec and $stderr_redirect and $var_get)
}
