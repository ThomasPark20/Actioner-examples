rule Exploit_Drupal_Fail2Install_SQLite_PHP_Webshell
{
    meta:
        description = "Detects SQLite database files with PHP code injected via CVE-2026-132165 Fail2Install. Attackers set SQLite DB path to a .php file and store PHP code as the site name."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://www.drupal.org/sa-core-2026-017"
        reference2 = "https://www.stepsecurity.io/blog/fail2install-cve-2026-132165"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $sqlite_header = "SQLite format 3" ascii
        $php_open1 = "<?php" ascii nocase
        $php_open2 = "<?" ascii
        $drupal_str1 = "drupal" ascii nocase
        $drupal_str2 = "install_profile" ascii nocase
        $drupal_str3 = "site_name" ascii nocase
        $shell_func1 = "system(" ascii nocase
        $shell_func2 = "exec(" ascii nocase
        $shell_func3 = "passthru(" ascii nocase
        $shell_func4 = "shell_exec(" ascii nocase
        $shell_func5 = "eval(" ascii nocase
        $shell_func6 = "base64_decode(" ascii nocase
        $shell_func7 = "assert(" ascii nocase

    condition:
        $sqlite_header at 0 and
        filesize < 10MB and
        (1 of ($php_open*)) and
        (1 of ($shell_func*) or 1 of ($drupal_str*))
}
